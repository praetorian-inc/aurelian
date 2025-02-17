package stages

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awstypes "github.com/aws/aws-sdk-go-v2/service/cloudcontrol/types"
	"github.com/cloudflare/backoff"

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
	out := make(chan types.EnrichedResourceDescription, 100) // Buffered to reduce blocking

	logger.Info("Listing resources")

	profile := options.GetOptionByName("profile", opts).Value
	regions, err := helpers.ParseRegionsOption(options.GetOptionByName(options.AwsRegionsOpt.Name, opts).Value, profile, opts)
	if err != nil {
		logger.Error(err.Error())
		close(out)
		return nil
	}

	config, err := helpers.GetAWSCfg(regions[0], profile, opts)
	if err != nil {
		logger.Error(err.Error())
		close(out)
		return nil
	}

	acctId, err := helpers.GetAccountId(config)
	if err != nil {
		logger.Error(err.Error())
		close(out)
		return nil
	}

	// Preload AWS clients
	cloudControlClients := make(map[string]*cloudcontrol.Client)
	regionSemaphores := make(map[string]chan struct{})

	for _, region := range regions {
		config, err := helpers.GetAWSCfg(region, profile, opts)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to get AWS config for %s ", region), slog.String("error", err.Error()))
			continue
		}

		cloudControlClients[region] = cloudcontrol.NewFromConfig(config)
		regionSemaphores[region] = make(chan struct{}, 5) // Limit concurrency per region
	}

	var wg sync.WaitGroup

	for rtype := range rtype {
		for region, cc := range cloudControlClients {
			if cc == nil {
				logger.Debug(fmt.Sprintf("Missing CloudControl Client for region %s", region))
				continue
			}

			if helpers.IsGlobalService(rtype) && region != "us-east-1" {
				logger.Debug(fmt.Sprintf("Skipping global resource type %s in region %s", rtype, region))
				continue
			}

			if !helpers.IsSupportedTypeInRegion(region, rtype) {
				logger.Debug(fmt.Sprintf("Skipping unsupported resource type %s in region %s", rtype, region))
				continue
			}

			logger.Debug(fmt.Sprintf("Listing resources of type %s in region: %s", rtype, region))
			wg.Add(1)

			go func(region, rtype string) {
				defer wg.Done()

				cc := cloudControlClients[region]

				paginator := cloudcontrol.NewListResourcesPaginator(cc, &cloudcontrol.ListResourcesInput{
					TypeName:   &rtype,
					MaxResults: aws.Int32(100),
				})

				// Create backoff with 5s initial interval, max 5m duration
				b := backoff.New(5*time.Minute, 5*time.Second)
				b.SetDecay(30 * time.Second)
			paginationLoop:
				for paginator.HasMorePages() {
					select {
					case <-ctx.Done():
						logger.Info(fmt.Sprintf("Context cancelled, stopping pagination for %s in region %s", rtype, region))
						break paginationLoop
					case regionSemaphores[region] <- struct{}{}: // Acquire semaphore
					}

					res, err := paginator.NextPage(ctx)
					if err != nil {
						<-regionSemaphores[region] // Release semaphore
						if strings.Contains(err.Error(), "TypeNotFoundException") {
							logger.Debug(fmt.Sprintf("The type %s is not available in region %s", rtype, region))
						} else if strings.Contains(err.Error(), "AccessDenied") || strings.Contains(err.Error(), "HandlerErrorCode: GeneralServiceException") {
							// HandlerErrorCode: GeneralServiceException seems to be a catch-all for access denied
							logger.Error(fmt.Sprintf("Access denied to list resources of type %s in region %s", rtype, region))
							logger.Debug(err.Error())
							return
						} else if strings.Contains(err.Error(), "UnsupportedActionException") {
							logger.Info(fmt.Sprintf("The type %s is not supported in region %s", rtype, region))
							return
						}
						if strings.Contains(err.Error(), "ThrottlingException") {
							delay := b.Duration()
							logger.Info(fmt.Sprintf("Rate limited, backing off for %v", delay), slog.String("region", region), slog.String("type", rtype))
							time.Sleep(delay)
							continue
						}

						logger.Error("Failed to ListResources", slog.String("region", region), slog.String("type", rtype), slog.String("err", err.Error()))
						break
					}

					<-regionSemaphores[region] // Release semaphore

					var resourceWg sync.WaitGroup
					for _, resource := range res.ResourceDescriptions {
						resourceWg.Add(1)

						go func(resource awstypes.ResourceDescription) {
							defer resourceWg.Done()
							erd := types.EnrichedResourceDescription{
								Identifier: *resource.Identifier,
								TypeName:   rtype,
								Region:     region,
								Properties: *resource.Properties,
								AccountId:  acctId,
							}
							erd.Arn = erd.ToArn()

							select {
							case out <- erd:
							case <-ctx.Done(): // Handle context cancellation
								return
							}
						}(resource)
					}
					resourceWg.Wait()
				}

				logger.Info("Completed collecting resource type " + rtype + " in region: " + region)
			}(region, rtype)
		}
	}

	go func() {
		wg.Wait()
		close(out)
		for _, ch := range regionSemaphores {
			close(ch)
		}
	}()

	return out
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
