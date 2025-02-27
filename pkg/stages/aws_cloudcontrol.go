package stages

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/aws/ratelimit"
	"github.com/aws/aws-sdk-go-v2/aws/retry"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AwsCloudControlListResources lists resources of a given type in a given region using the Cloud Control API.
// This should be the primary method of listing resources in AWS.
func AwsCloudControlListResources(ctx context.Context, opts []*types.Option, rtype <-chan string) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "CloudControlListResources")
	out := make(chan types.EnrichedResourceDescription, 50000) // Buffered to reduce blocking

	var resourceCount int64

	logger.Info("Listing resources")

	profile := options.GetOptionByName("profile", opts).Value
	regions, err := helpers.ParseRegionsOption(options.GetOptionByName(options.AwsRegionsOpt.Name, opts).Value, profile, opts)
	if err != nil {
		logger.Error(err.Error())
		close(out)
		return out
	}

	config, err := helpers.GetAWSCfg(regions[0], profile, opts)
	if err != nil {
		logger.Error(err.Error())
		close(out)
		return out
	}

	acctId, err := helpers.GetAccountId(config)
	if err != nil {
		logger.Error(err.Error())
		close(out)
		return out
	}

	// Preload AWS clients
	cloudControlClients := make(map[string]*cloudcontrol.Client)

	globalSemaphore := make(chan struct{}, 500)
	regionSemaphores := make(map[string]chan struct{})

	for _, region := range regions {
		config, err := helpers.GetAWSCfg(region, profile, opts)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to get AWS config for %s ", region), slog.String("error", err.Error()))
			continue
		}
		//config.RetryMaxAttempts = 10 // Overwrite the Max Retry for ThrottlingException
		var standardOptions []func(*retry.StandardOptions)
		standardOptions = append(standardOptions, func(so *retry.StandardOptions) {
			so.MaxAttempts = 10
			so.RateLimiter = ratelimit.None
			so.MaxBackoff = time.Second * 60
		})
		var adaptiveOptions []func(*retry.AdaptiveModeOptions)
		adaptiveOptions = append(adaptiveOptions, func(ao *retry.AdaptiveModeOptions) {
			ao.StandardOptions = append(ao.StandardOptions, standardOptions...)
		})
		var retryer aws.RetryerV2
		retryer = retry.NewAdaptiveMode(adaptiveOptions...)

		config.Retryer = func() aws.Retryer {
			return retryer
		}
		cloudControlClients[region] = cloudcontrol.NewFromConfig(config)
		regionSemaphores[region] = make(chan struct{}, 10) // Limit concurrency per region
	}

	var wg sync.WaitGroup

	// Process resource types
	go func() {
		defer func() {
			// Proper cleanup when all resource type processing is done
			wg.Wait()
			logger.Info(fmt.Sprintf("Total resources processed: %d", atomic.LoadInt64(&resourceCount)))
			close(out)
			for _, ch := range regionSemaphores {
				close(ch)
			}
			close(globalSemaphore)
		}()

		for resourceType := range rtype {
			// Validate resource type format
			if !IsValidResourceType(resourceType) {
				logger.Error(fmt.Sprintf("Invalid resource type format: %s", resourceType))
				continue
			}

			for region, cc := range cloudControlClients {
				if cc == nil {
					logger.Debug(fmt.Sprintf("Missing CloudControl Client for region %s", region))
					continue
				}

				if helpers.IsGlobalService(resourceType) && region != "us-east-1" {
					logger.Debug(fmt.Sprintf("Skipping global resource type %s in region %s", resourceType, region))
					continue
				}

				if !helpers.IsSupportedTypeInRegion(region, resourceType) {
					logger.Debug(fmt.Sprintf("Skipping unsupported resource type %s in region %s", resourceType, region))
					continue
				}

				logger.Debug(fmt.Sprintf("Listing resources of type %s in region: %s", resourceType, region))
				wg.Add(1)

				go func(region, resourceType string) {
					defer wg.Done()

					cc := cloudControlClients[region]

					paginator := cloudcontrol.NewListResourcesPaginator(cc, &cloudcontrol.ListResourcesInput{
						TypeName:   &resourceType,
						MaxResults: aws.Int32(100),
					})

					var resourceWg sync.WaitGroup
					resourceSemaphore := make(chan struct{}, 10) // Limit resource goroutines
					defer close(resourceSemaphore)

				paginationLoop:
					for paginator.HasMorePages() {
						// Check for context cancellation
						select {
						case <-ctx.Done():
							logger.Info(fmt.Sprintf("Context cancelled, stopping pagination for %s in region %s", resourceType, region))
							break paginationLoop
						default:
							// Continue processing
						}

						// Acquire both semaphores with proper error handling
						select {
						case <-ctx.Done():
							break paginationLoop
						case globalSemaphore <- struct{}{}:
							// Acquired global semaphore
						}

						select {
						case <-ctx.Done():
							<-globalSemaphore // Release global semaphore if we can't acquire regional
							break paginationLoop
						case regionSemaphores[region] <- struct{}{}:
							// Acquired regional semaphore
						}

						// Execute API call with proper semaphore release
						res, err := paginator.NextPage(ctx)

						// Always release semaphores regardless of errors
						<-regionSemaphores[region]
						<-globalSemaphore

						if err != nil {
							errMsg := err.Error()
							// Check for different error types
							switch {
							case strings.Contains(errMsg, "TypeNotFoundException"):
								logger.Debug(fmt.Sprintf("The type %s is not available in region %s", resourceType, region))
								return

							case strings.Contains(errMsg, "is not authorized to perform") || strings.Contains(errMsg, "AccessDeniedException"):
								logger.Error(fmt.Sprintf("Access denied to list resources of type %s in region %s", resourceType, region))
								logger.Debug(errMsg)
								return

							case strings.Contains(errMsg, "UnsupportedActionException"):
								logger.Info(fmt.Sprintf("The type %s is not supported in region %s", resourceType, region))
								return

							case strings.Contains(errMsg, "ThrottlingException"):
								// Log throttling but don't terminate - let AWS SDK retry with backoff
								logger.Info("Rate limited", slog.String("region", region), slog.String("type", resourceType))
								return

							default:
								logger.Error("Failed to ListResources",
									slog.String("region", region),
									slog.String("type", resourceType),
									slog.String("err", errMsg))
							}
							// For non-terminal errors, continue to next page
							return
						}

						// Process resources with controlled concurrency
						for _, resource := range res.ResourceDescriptions {
							resourceWg.Add(1)

							// Reuse resource structs to avoid unnecessary allocations
							resourceCopy := resource // Copy to avoid race conditions

							// Use a semaphore to limit resource goroutines
							select {
							case <-ctx.Done():
								resourceWg.Done()
								continue
							case resourceSemaphore <- struct{}{}:
								// Acquired resource semaphore
							}

							go func() {
								defer resourceWg.Done()
								defer func() { <-resourceSemaphore }() // Release resource semaphore

								// set the region to empty string for global services
								var erdRegion string
								if helpers.IsGlobalService(resourceType) {
									erdRegion = ""
								} else {
									erdRegion = region
								}

								erd := types.EnrichedResourceDescription{
									Identifier: *resourceCopy.Identifier,
									TypeName:   resourceType,
									Region:     erdRegion,
									Properties: *resourceCopy.Properties,
									AccountId:  acctId,
								}

								// some resources have a different ARN format than the identifier
								// so we need to parse the identifier to get the ARN
								parsed, err := arn.Parse(*resource.Identifier)
								if err != nil {
									logger.Debug("Failed to parse ARN: "+*resource.Identifier, slog.String("error", err.Error()))
									erd.Arn = erd.ToArn()
								} else {
									logger.Debug("Parsed ARN: "+*resource.Identifier, slog.String("arn", parsed.String()))
									erd.Arn = parsed
								}

								erd.Arn = erd.ToArn()

								atomic.AddInt64(&resourceCount, 1)

								// Non-blocking channel send with context cancellation
								select {
								case out <- erd:
									// Successfully sent
								case <-ctx.Done():
									// Context cancelled, don't block
									return
								}
							}()
						}
					}

					// Wait for all resource goroutines to finish before moving to next region/type
					resourceWg.Wait()
					logger.Info("Completed collecting resource type " + resourceType + " in region: " + region)
				}(region, resourceType)
			}
		}
	}()

	return out
}

// Helper function to validate resource type format
func IsValidResourceType(resourceType string) bool {
	// Basic format validation for AWS resource types
	// Should match pattern like: AWS::Service::Resource
	regex := regexp.MustCompile(`^[A-Za-z0-9]+::[A-Za-z0-9]+::[A-Za-z0-9]+$`)
	return regex.MatchString(resourceType)
}

// AwsCloudControlGetResource gets a single resource using the Cloud Control API.
func AwsCloudControlGetResource(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "CloudControlGetResource")
	out := make(chan types.EnrichedResourceDescription)
	logger.Info("Getting resource to populate properties")
	go func() {
		defer close(out)
		for resource := range in {
			logger.Info("Now getting resource: " + resource.Identifier)
			cfg, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error(err.Error())
				continue
			}

			cc := cloudcontrol.NewFromConfig(cfg)

			params := &cloudcontrol.GetResourceInput{
				Identifier: &resource.Identifier,
				TypeName:   &resource.TypeName,
			}

			retries := 3
			backoff := 1000

			for i := 0; i < retries; i++ {
				res, err := cc.GetResource(ctx, params)
				if err != nil && strings.Contains(err.Error(), "ThrottlingException") {
					logger.Info("ThrottlingException encountered. Retrying in " + strconv.Itoa(backoff) + "ms")
					b := time.Duration(backoff) * time.Millisecond * time.Duration(i)
					time.Sleep(b)
					continue
				}

				if err != nil {
					logger.Error("Error getting resource: %s, %s", resource.Identifier, err)
					break
				}

				out <- types.EnrichedResourceDescription{
					Identifier: resource.Identifier,
					TypeName:   resource.TypeName,
					Region:     resource.Region,
					Properties: res.ResourceDescription.Properties,
					AccountId:  resource.AccountId,
				}
				break
			}
		}
	}()
	return out
}
