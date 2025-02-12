package stages

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	awstypes "github.com/aws/aws-sdk-go-v2/service/cloudcontrol/types"
	"strconv"
	"strings"
	"sync"
	"time"

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
			logger.Error("Failed to get AWS config for", "region", region, "err:", err)
			continue
		}

		cloudControlClients[region] = cloudcontrol.NewFromConfig(config)
		regionSemaphores[region] = make(chan struct{}, 5) // Limit concurrency per region
	}

	var wg sync.WaitGroup

	for rtype := range rtype {
		for region, cc := range cloudControlClients {
			if cc == nil {
				logger.Debug("Missing CloudControl Client for region", region)
				continue
			}

			if helpers.IsGlobalService(rtype) && region != "us-east-1" {
				logger.Debug("Skipping global resource type %s in region %s", rtype, region)
				continue
			}

			logger.Debug("Listing resources of type %s in region: %s", rtype, region)
			wg.Add(1)

			go func(region, rtype string) {
				defer wg.Done()
				cc := cloudControlClients[region]

				paginator := cloudcontrol.NewListResourcesPaginator(cc, &cloudcontrol.ListResourcesInput{
					TypeName:   &rtype,
					MaxResults: aws.Int32(100),
				})

				for paginator.HasMorePages() {
					select {
					case <-ctx.Done():
						logger.Info("Context cancelled, stopping pagination for", rtype, "in region", region)
						break
					case regionSemaphores[region] <- struct{}{}: // Acquire semaphore
					}

					res, err := paginator.NextPage(ctx)
					if err != nil {
						<-regionSemaphores[region] // Release semaphore
						if strings.Contains(err.Error(), "TypeNotFoundException") {
							logger.Debug("The type %s is not available in region %s", rtype, region)
						} else {
							logger.Debug("Failed to ListResources", "region", region, "type", rtype, "err", err.Error())
						}
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
