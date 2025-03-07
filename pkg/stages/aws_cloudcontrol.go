package stages

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	cctypes "github.com/aws/aws-sdk-go-v2/service/cloudcontrol/types"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	options "github.com/praetorian-inc/nebula/pkg/links/opts"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AwsCloudControlListResources lists resources of a given type in a given region using the Cloud Control API.
// This should be the primary method of listing resources in AWS.
func AwsCloudControlListResources(ctx context.Context, opts []*types.Option, rtype <-chan string) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "CloudControlListResources")

	out := make(chan types.EnrichedResourceDescription)
	logger.Info("Listing resources")

	profile := options.GetOptionByName("profile", opts).Value
	regions, err := helpers.ParseRegionsOption(options.GetOptionByName(options.AwsRegionsOpt.Name, opts).Value, profile, opts)
	if err != nil {
		logger.Error(err.Error())
		return nil
	}

	config, err := helpers.GetAWSCfg(regions[0], profile, opts)
	if err != nil {
		logger.Error(err.Error())
		return nil
	}
	acctId, err := helpers.GetAccountId(config)
	if err != nil {
		logger.Error(err.Error())
		return nil
	}

	var wg sync.WaitGroup

	// Create semaphores for each region to limit concurrent resource processing
	regionSemaphores := make(map[string]chan struct{})
	for _, region := range regions {
		regionSemaphores[region] = make(chan struct{}, 5)
	}

	for rtype := range rtype {
		for _, region := range regions {
			// Skip non us-east-1 regions for global services
			if helpers.IsGlobalService(rtype) && region != "us-east-1" {
				continue
			}

			logger.Info("Listing resources of type " + rtype + " in region: " + region)
			wg.Add(1)
			go func(region string, rtype string) {
				defer wg.Done()
				config, _ := helpers.GetAWSCfg(region, profile, opts)
				cc := cloudcontrol.NewFromConfig(config)
				params := &cloudcontrol.ListResourcesInput{
					TypeName: &rtype,
				}

				for {
					res, err := cc.ListResources(ctx, params)
					if err != nil {
						if strings.Contains(err.Error(), "TypeNotFoundException") {
							logger.Info("The type %s is not available in region %s", rtype, region)
							break
						}
						logger.Debug(err.Error())
						break
					}

					var resourceWg sync.WaitGroup
					for _, resource := range res.ResourceDescriptions {
						resourceWg.Add(1)
						go func(resource *cctypes.ResourceDescription) {
							defer resourceWg.Done()
							regionSemaphores[region] <- struct{}{}
							defer func() { <-regionSemaphores[region] }()

							erd := types.EnrichedResourceDescription{
								Identifier: *resource.Identifier,
								TypeName:   rtype,
								Region:     region,
								Properties: *resource.Properties,
								AccountId:  acctId,
							}
							erd.Arn = erd.ToArn()
							out <- erd
						}(&resource)
					}
					resourceWg.Wait()

					if res.NextToken == nil {
						break
					}
					params.NextToken = res.NextToken
				}
				logger.Info("Completed collecting resource type " + rtype + " in region: " + region)
			}(region, rtype)
		}
	}

	go func() {
		wg.Wait()
		close(out)
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
