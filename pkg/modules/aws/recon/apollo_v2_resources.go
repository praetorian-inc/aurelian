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
	"github.com/praetorian-inc/aurelian/pkg/types"
	"golang.org/x/sync/errgroup"
)

// gatherResources enumerates AWS resources using CloudControl SDK with bounded concurrency.
// Returns all discovered resources or an error if enumeration fails critically.
func (a *ApolloV2) gatherResources(ctx context.Context) ([]types.EnrichedResourceDescription, error) {
	// Create channel for streaming resources
	resourceCh := make(chan types.EnrichedResourceDescription, 100)
	var resources []types.EnrichedResourceDescription

	// Start collector goroutine
	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		for r := range resourceCh {
			resources = append(resources, r)
		}
	}()

	// Use errgroup with bounded concurrency for resource enumeration
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(25) // Bounded concurrency limit

	// Enumerate each resource type across all regions
	for _, resourceType := range a.ResourceTypes {
		for _, region := range a.Regions {
			resourceType, region := resourceType, region // Capture for goroutine

			g.Go(func() error {
				return a.listResourcesInRegion(gCtx, resourceType, region, resourceCh)
			})
		}
	}

	// Wait for all enumerations and check for errors
	if err := g.Wait(); err != nil {
		close(resourceCh)
		collectWg.Wait()
		return nil, fmt.Errorf("resource enumeration failed: %w", err)
	}

	// Close channel and wait for collector
	close(resourceCh)
	collectWg.Wait()

	return resources, nil
}

// listResourcesInRegion lists all resources of a given type in a region using CloudControl API.
// This replaces the Janus CloudControl link pattern.
func (a *ApolloV2) listResourcesInRegion(ctx context.Context, resourceType, region string, resourceCh chan<- types.EnrichedResourceDescription) error {
	// Skip global services in non-us-east-1 regions
	if a.isGlobalService(resourceType, region) {
		slog.Debug("Skipping global service", "type", resourceType, "region", region)
		return nil
	}

	slog.Debug("Listing resources in region", "type", resourceType, "region", region, "profile", a.Profile)

	// Get account ID
	accountId, err := helpers.GetAccountId(a.config)
	if err != nil {
		return fmt.Errorf("failed to get account ID: %w", err)
	}

	// Get CloudControl client for this region
	cc, ok := a.cloudControlClients[region]
	if !ok {
		return fmt.Errorf("no CloudControl client for region %s", region)
	}

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
			if shouldSkip := a.handleCloudControlError(resourceType, region, err); shouldSkip {
				return nil // Skip this resource type/region combination
			}
			return fmt.Errorf("failed to list resources of type %s in region %s: %w", resourceType, region, err)
		}

		// Convert and send each resource
		for _, resource := range res.ResourceDescriptions {
			erd := a.resourceDescriptionToERD(resource, resourceType, accountId, region)

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
func (a *ApolloV2) resourceDescriptionToERD(resource cctypes.ResourceDescription, rType, accountId, region string) types.EnrichedResourceDescription {
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

	return erd
}

// isGlobalService determines if a resource type is a global AWS service.
func (a *ApolloV2) isGlobalService(resourceType, region string) bool {
	return helpers.IsGlobalService(resourceType) && region != "us-east-1"
}

// handleCloudControlError processes CloudControl API errors and determines if enumeration should continue.
// Returns true if the error indicates this resource type/region should be skipped.
func (a *ApolloV2) handleCloudControlError(resourceType, region string, err error) bool {
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
