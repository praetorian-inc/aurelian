package secrets

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	helpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	cclist "github.com/praetorian-inc/aurelian/pkg/aws/cloudcontrol"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
	"github.com/praetorian-inc/aurelian/pkg/scanner"
	titusTypes "github.com/praetorian-inc/titus/pkg/types"
	"github.com/praetorian-inc/titus/pkg/validator"
	"golang.org/x/sync/errgroup"
)

// FindSecrets scans AWS resources for secrets using Titus.
// It enumerates resources via CloudControl, extracts content with per-type extractors,
// and scans each piece of content for secrets.
func FindSecrets(ctx context.Context, opts ScanOptions) ([]output.SecretFinding, error) {
	// Resolve regions
	regions, err := resolveRegions(opts)
	if err != nil {
		return nil, fmt.Errorf("resolve regions: %w", err)
	}

	// Resolve resource types
	resourceTypes := resolveResourceTypes(opts.ResourceTypes)
	if len(resourceTypes) == 0 {
		return nil, fmt.Errorf("no supported resource types selected")
	}

	slog.Info("starting find-secrets scan",
		"regions", len(regions),
		"resource_types", len(resourceTypes),
		"concurrency", opts.Concurrency,
	)

	// Set up the persistent scanner
	ps, err := scanner.NewPersistentScanner(opts.DBPath)
	if err != nil {
		return nil, fmt.Errorf("create scanner: %w", err)
	}
	defer ps.Close()

	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 5
	}

	// Set up validator engine if verification is enabled
	var validatorEngine *validator.Engine
	if opts.Verify {
		validatorEngine = validator.NewEngine(concurrency,
			validator.NewAWSValidator(),
		)
	}

	// Enumerate resources using CloudControl
	lister := cclist.NewCloudControlLister(plugin.AWSCommonRecon{
		AWSReconBase: plugin.AWSReconBase{
			Profile:    opts.Profile,
			ProfileDir: opts.ProfileDir,
		},
		Concurrency:  concurrency,
		Regions:      regions,
		ResourceType: resourceTypes,
	})

	resourceMap, err := lister.List(regions, resourceTypes)
	if err != nil {
		return nil, fmt.Errorf("enumerate resources: %w", err)
	}

	// Flatten resources by region for processing
	type regionResource struct {
		region   string
		resource output.CloudResource
	}

	var allResources []regionResource
	for key, resources := range resourceMap {
		// key format is "region/ResourceType"
		parts := strings.SplitN(key, "/", 2)
		region := parts[0]
		for _, r := range resources {
			allResources = append(allResources, regionResource{
				region:   region,
				resource: r,
			})
		}
	}

	slog.Info("enumerated resources", "total", len(allResources))

	if len(allResources) == 0 {
		return nil, nil
	}

	// Process resources using cross-region rate limiting and errgroup
	var (
		findings []output.SecretFinding
		mu       sync.Mutex
	)

	// Group resources by region for cross-region rate limiting
	byRegion := make(map[string][]output.CloudResource)
	for _, rr := range allResources {
		byRegion[rr.region] = append(byRegion[rr.region], rr.resource)
	}

	regionList := make([]string, 0, len(byRegion))
	for r := range byRegion {
		regionList = append(regionList, r)
	}

	actor := ratelimit.NewCrossRegionActor(concurrency)
	err = actor.ActInRegions(regionList, func(region string) error {
		resources := byRegion[region]

		// Create AWS config for this region
		cfg, err := helpers.NewAWSConfig(helpers.AWSConfigInput{
			Region:     region,
			Profile:    opts.Profile,
			ProfileDir: opts.ProfileDir,
		})
		if err != nil {
			return fmt.Errorf("create AWS config for %s: %w", region, err)
		}

		// Process resources in parallel within the region
		g, gCtx := errgroup.WithContext(ctx)
		g.SetLimit(concurrency)

		for _, resource := range resources {
			resource := resource
			g.Go(func() error {
				regionFindings, err := extractAndScan(gCtx, cfg, resource, opts, ps, validatorEngine)
				if err != nil {
					slog.Warn("extract and scan failed",
						"type", resource.ResourceType,
						"id", resource.ResourceID,
						"region", region,
						"error", err,
					)
					return nil // Don't fail the whole scan for one resource
				}

				if len(regionFindings) > 0 {
					mu.Lock()
					findings = append(findings, regionFindings...)
					mu.Unlock()
				}

				return nil
			})
		}

		return g.Wait()
	})
	if err != nil {
		return findings, fmt.Errorf("scan resources: %w", err)
	}

	slog.Info("find-secrets scan complete", "findings", len(findings))
	return findings, nil
}

// extractAndScan extracts content from a resource and scans it for secrets.
func extractAndScan(ctx context.Context, cfg aws.Config, resource output.CloudResource, opts ScanOptions, ps *scanner.PersistentScanner, ve *validator.Engine) ([]output.SecretFinding, error) {
	extractor := GetExtractor(resource.ResourceType)
	if extractor == nil {
		return nil, nil
	}

	contents, err := extractor.Extract(ctx, cfg, resource, opts)
	if err != nil {
		return nil, err
	}

	var findings []output.SecretFinding
	for _, ec := range contents {
		if len(ec.Content) == 0 {
			continue
		}

		blobID := titusTypes.ComputeBlobID(ec.Content)
		provenance := titusTypes.FileProvenance{
			FilePath: ec.Provenance.FilePath,
		}

		matches, err := ps.ScanContent(ec.Content, blobID, provenance)
		if err != nil {
			slog.Warn("scan content failed",
				"file", ec.Provenance.FilePath,
				"error", err,
			)
			continue
		}

		for _, match := range matches {
			finding := output.SecretFinding{
				ResourceRef: ec.Provenance.ResourceID,
				RuleName:    match.RuleName,
				RuleTextID:  match.RuleID,
				Match:       string(match.Snippet.Matching),
				FilePath:    ec.Provenance.FilePath,
				LineNumber:  match.Location.Source.Start.Line,
				Confidence:  "high",
			}

			if ve != nil {
				result, err := ve.ValidateMatch(ctx, match)
				if err == nil && result != nil {
					finding.Verified = string(result.Status)
					finding.VerifiedMessage = result.Message
				}
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

// resolveRegions resolves the "all" keyword to actual enabled regions.
func resolveRegions(opts ScanOptions) ([]string, error) {
	if len(opts.Regions) == 1 && strings.EqualFold(opts.Regions[0], "all") {
		return helpers.EnabledRegions(opts.Profile, opts.ProfileDir)
	}
	if len(opts.Regions) == 0 {
		return helpers.EnabledRegions(opts.Profile, opts.ProfileDir)
	}
	return opts.Regions, nil
}

// resolveResourceTypes resolves the "all" keyword to the supported set.
func resolveResourceTypes(types []string) []string {
	if len(types) == 0 {
		return SupportedResourceTypes()
	}
	if len(types) == 1 && strings.EqualFold(types[0], "all") {
		return SupportedResourceTypes()
	}

	// Filter to only supported types
	supported := make(map[string]bool)
	for _, t := range SupportedResourceTypes() {
		supported[t] = true
	}

	var result []string
	for _, t := range types {
		if supported[t] {
			result = append(result, t)
		} else {
			slog.Warn("unsupported resource type", "type", t)
		}
	}
	return result
}
