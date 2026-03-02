package secrets

import (
	"context"
	"log/slog"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	helpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/scanner"
	titusTypes "github.com/praetorian-inc/titus/pkg/types"
	"github.com/praetorian-inc/titus/pkg/validator"
)

// NewResourceScanner returns a pipeline-compatible function that extracts content
// from an AWSResource and scans it for secrets using Titus. AWS configs are
// cached per-region for efficiency.
func NewResourceScanner(opts ScanOptions, ps *scanner.PersistentScanner, ve *validator.Engine) func(output.AWSResource, *pipeline.P[model.AurelianModel]) error {
	var (
		configCache = make(map[string]aws.Config)
		configMu    sync.Mutex
	)

	getConfig := func(region string) (aws.Config, error) {
		configMu.Lock()
		defer configMu.Unlock()

		if cfg, ok := configCache[region]; ok {
			return cfg, nil
		}

		cfg, err := helpers.NewAWSConfig(helpers.AWSConfigInput{
			Region:     region,
			Profile:    opts.Profile,
			ProfileDir: opts.ProfileDir,
		})
		if err != nil {
			return aws.Config{}, err
		}
		configCache[region] = cfg
		return cfg, nil
	}

	return func(resource output.AWSResource, out *pipeline.P[model.AurelianModel]) error {
		extractor := GetExtractor(resource.ResourceType)
		if extractor == nil {
			return nil
		}

		cfg, err := getConfig(resource.Region)
		if err != nil {
			slog.Warn("failed to create AWS config, skipping resource",
				"resource", resource.ResourceID, "region", resource.Region, "error", err)
			return nil
		}

		contents, err := extractor.Extract(context.Background(), cfg, resource, opts)
		if err != nil {
			slog.Warn("extract failed, skipping resource",
				"type", resource.ResourceType, "id", resource.ResourceID, "error", err)
			return nil
		}

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
					"file", ec.Provenance.FilePath, "error", err)
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
					result, err := ve.ValidateMatch(context.Background(), match)
					if err == nil && result != nil {
						finding.Verified = string(result.Status)
						finding.VerifiedMessage = result.Message
					}
				}

				out.Send(finding)
			}
		}

		return nil
	}
}
