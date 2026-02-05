package recon

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	cctypes "github.com/aws/aws-sdk-go-v2/service/cloudcontrol/types"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/dispatcher"
	"github.com/praetorian-inc/aurelian/pkg/links/options"
	"github.com/praetorian-inc/aurelian/pkg/orchestrator"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// FindAWSSecretsV2 is the refactored version using plain Go patterns
// instead of janus-framework chains.
type FindAWSSecretsV2 struct {
	Profile       string
	Regions       []string
	ResourceTypes []string
	MaxEvents     int
	MaxStreams    int
	NewestFirst   bool

	// Internal state
	cloudControlClients map[string]*cloudcontrol.Client
	config              aws.Config
}

// NewFindAWSSecretsV2 creates a new v2 secret finder with sensible defaults.
func NewFindAWSSecretsV2(profile string, regions []string) *FindAWSSecretsV2 {
	return &FindAWSSecretsV2{
		Profile:       profile,
		Regions:       regions,
		ResourceTypes: dispatcher.SupportedAWSSecretTypes(),
		MaxEvents:     10000,
		MaxStreams:    10,
		NewestFirst:   false,
	}
}

// Run executes the AWS secrets finding workflow.
// Returns the secrets found as NpInput objects.
func (f *FindAWSSecretsV2) Run(ctx context.Context) ([]types.NpInput, error) {
	// 1. Initialize AWS clients
	if err := f.initialize(ctx); err != nil {
		return nil, fmt.Errorf("initialization failed: %w", err)
	}

	// 2. Create channels for resource streaming
	resourceCh := make(chan *types.EnrichedResourceDescription, 100)
	resultCh := make(chan types.NpInput, 100)

	// 3. Start resource enumeration in background
	var enumErr error
	var enumWg sync.WaitGroup
	enumWg.Add(1)
	go func() {
		defer enumWg.Done()
		defer close(resourceCh)
		enumErr = f.enumerateResources(ctx, resourceCh)
	}()

	// 4. Start result collection in background
	var results []types.NpInput
	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		for result := range resultCh {
			results = append(results, result)
		}
	}()

	// 5. Process resources through orchestrator
	procErr := orchestrator.ProcessAWSSecrets(ctx, resourceCh, resultCh,
		orchestrator.WithConcurrencyLimit(25),
		orchestrator.WithProcessOptions(&dispatcher.ProcessOptions{
			AWSProfile:  f.Profile,
			Regions:     f.Regions,
			MaxEvents:   f.MaxEvents,
			MaxStreams:  f.MaxStreams,
			NewestFirst: f.NewestFirst,
		}),
	)

	// 6. Close result channel after processing completes
	close(resultCh)

	// 7. Wait for all goroutines to finish
	enumWg.Wait()
	collectWg.Wait()

	// 8. Check for errors
	if enumErr != nil {
		return nil, fmt.Errorf("enumeration failed: %w", enumErr)
	}
	if procErr != nil {
		return nil, fmt.Errorf("processing failed: %w", procErr)
	}

	return results, nil
}

// defaultCacheOptions returns the default cache options required by GetAWSCfg.
// These options are needed to initialize the AWS cache system.
func (f *FindAWSSecretsV2) defaultCacheOptions() []*types.Option {
	return []*types.Option{
		&options.AwsCacheDirOpt,
		&options.AwsCacheExtOpt,
		&options.AwsCacheTTLOpt,
		&options.AwsDisableCacheOpt,
		&options.AwsCacheErrorRespOpt,
		&options.AwsCacheErrorRespTypesOpt,
	}
}

// initialize sets up AWS clients for all regions.
func (f *FindAWSSecretsV2) initialize(ctx context.Context) error {
	opts := f.defaultCacheOptions()

	// Load base AWS config
	cfg, err := helpers.GetAWSCfg(f.Regions[0], f.Profile, opts, "moderate")
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}
	f.config = cfg

	// Create CloudControl clients for each region
	f.cloudControlClients = make(map[string]*cloudcontrol.Client)
	for _, region := range f.Regions {
		regionCfg, err := helpers.GetAWSCfg(region, f.Profile, opts, "moderate")
		if err != nil {
			return fmt.Errorf("failed to load AWS config for region %s: %w", region, err)
		}
		f.cloudControlClients[region] = cloudcontrol.NewFromConfig(regionCfg)
	}

	return nil
}

// enumerateResources streams AWS resources to the provided channel.
// This replaces the CloudControl link from janus-framework.
func (f *FindAWSSecretsV2) enumerateResources(ctx context.Context, resourceCh chan<- *types.EnrichedResourceDescription) error {
	var wg sync.WaitGroup
	errCh := make(chan error, len(f.ResourceTypes)*len(f.Regions))

	// Enumerate each resource type across all regions
	for _, resourceType := range f.ResourceTypes {
		for _, region := range f.Regions {
			// Skip global services in non-us-east-1 regions
			if f.isGlobalService(resourceType, region) {
				slog.Debug("Skipping global service", "type", resourceType, "region", region)
				continue
			}

			wg.Add(1)
			go func(rType, reg string) {
				defer wg.Done()
				if err := f.listResourcesInRegion(ctx, rType, reg, resourceCh); err != nil {
					errCh <- err
				}
			}(resourceType, region)
		}
	}

	// Wait for all enumerations to complete
	wg.Wait()
	close(errCh)

	// Collect any errors
	var errs []error
	for err := range errCh {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("enumeration encountered %d errors: %v", len(errs), errs[0])
	}

	return nil
}

// listResourcesInRegion lists all resources of a given type in a region.
// This is extracted from cloud_control_list.go's listResourcesInRegion method.
func (f *FindAWSSecretsV2) listResourcesInRegion(ctx context.Context, resourceType, region string, resourceCh chan<- *types.EnrichedResourceDescription) error {
	slog.Debug("Listing resources in region", "type", resourceType, "region", region, "profile", f.Profile)

	opts := f.defaultCacheOptions()

	// Get account ID
	regionCfg, err := helpers.GetAWSCfg(region, f.Profile, opts, "moderate")
	if err != nil {
		return fmt.Errorf("failed to get AWS config for region %s: %w", region, err)
	}

	accountId, err := helpers.GetAccountId(regionCfg)
	if err != nil {
		return fmt.Errorf("failed to get account ID for region %s: %w", region, err)
	}

	// Get CloudControl client for this region
	cc := f.cloudControlClients[region]

	// Paginate through all resources
	paginator := cloudcontrol.NewListResourcesPaginator(cc, &cloudcontrol.ListResourcesInput{
		TypeName:   &resourceType,
		MaxResults: aws.Int32(100),
	})

	for paginator.HasMorePages() {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		res, err := paginator.NextPage(ctx)
		if err != nil {
			// Handle known error types gracefully
			if shouldSkip := f.handleCloudControlError(resourceType, region, err); shouldSkip {
				return nil // Skip this resource type/region combination
			}
			return fmt.Errorf("failed to list resources of type %s in region %s: %w", resourceType, region, err)
		}

		// Convert and send each resource
		for _, resource := range res.ResourceDescriptions {
			erd := f.resourceDescriptionToERD(resource, resourceType, accountId, region)

			// Send to channel (non-blocking with context check)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case resourceCh <- erd:
			}
		}
	}

	return nil
}

// resourceDescriptionToERD converts CloudControl resource description to EnrichedResourceDescription.
// Extracted from cloud_control_list.go's resourceDescriptionToERD method.
func (f *FindAWSSecretsV2) resourceDescriptionToERD(resource cctypes.ResourceDescription, rType, accountId, region string) *types.EnrichedResourceDescription {
	var erdRegion string
	if helpers.IsGlobalService(rType) {
		erdRegion = ""
	} else {
		erdRegion = region
	}

	erd := types.NewEnrichedResourceDescription(
		*resource.Identifier,
		rType,
		erdRegion,
		accountId,
		*resource.Properties,
	)

	return &erd
}

// isGlobalService determines if a resource type is a global AWS service.
func (f *FindAWSSecretsV2) isGlobalService(resourceType, region string) bool {
	return helpers.IsGlobalService(resourceType) && region != "us-east-1"
}

// handleCloudControlError processes CloudControl API errors and determines if enumeration should continue.
// Returns true if the error indicates this resource type/region should be skipped.
func (f *FindAWSSecretsV2) handleCloudControlError(resourceType, region string, err error) bool {
	errMsg := err.Error()

	// These error types indicate the resource type is not available/supported
	// Log and skip gracefully
	skipErrors := []string{
		"TypeNotFoundException",
		"UnsupportedActionException",
		"is not authorized to perform",
		"AccessDeniedException",
	}
	for _, skipErr := range skipErrors {
		if strings.Contains(errMsg, skipErr) {
			slog.Debug("Resource type not available", "type", resourceType, "region", region, "error", errMsg)
			return true
		}
	}

	// Throttling errors should be retried by the SDK, but if we hit here just log
	if strings.Contains(errMsg, "ThrottlingException") {
		slog.Warn("Rate limited during enumeration", "type", resourceType, "region", region)
		return false
	}

	return false
}
