package stages

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

// AwsCloudWatchDestinationCheckResourcePolicy checks the resource access policy for CloudWatch Destinations.
func AwsCloudWatchDestinationCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "CloudWatchDestinationCheckResourcePolicy")
	logger.Info("Checking CloudWatch destination resource access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			logsClient := cloudwatchlogs.NewFromConfig(config)
			logger.Info("Trying to get CloudWatch destination resource access policy for " + resource.Identifier)

			destinationsInput := &cloudwatchlogs.DescribeDestinationsInput{
				DestinationNamePrefix: aws.String(resource.Identifier),
			}
			destinationsOutput, err := logsClient.DescribeDestinations(ctx, destinationsInput)
			if err != nil {
				logger.Debug("Could not get CloudWatch destination resource access policy for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				var newProperties string
				for _, destination := range destinationsOutput.Destinations {
					if destination.DestinationName == &resource.Identifier {
						policyResultString := utils.CheckResourceAccessPolicy(*destination.AccessPolicy)

						lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
						newProperties = resource.Properties.(string)[:lastBracketIndex] + "," + policyResultString + "}"

						out <- types.EnrichedResourceDescription{
							Identifier: resource.Identifier,
							TypeName:   resource.TypeName,
							Region:     resource.Region,
							Properties: newProperties,
							AccountId:  resource.AccountId,
						}
					}
				}
			}
		}
		close(out)
	}()
	return out
}
