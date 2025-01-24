package stages

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

func AwsEventBusCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "EventBusCheckResourcePolicy")
	logger.Info("Checking event bus resource access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			eventsClient := eventbridge.NewFromConfig(config)

			describeInput := &eventbridge.DescribeEventBusInput{
				Name: aws.String(resource.Identifier),
			}
			describeOutput, err := eventsClient.DescribeEventBus(ctx, describeInput)
			if err != nil {
				logger.Debug("Could not get event bus resource access policy for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else if describeOutput.Policy == nil {
				logger.Debug("Could not get event bus resource access policy for " + resource.Identifier + ", no policy found")
				out <- resource
			} else {
				policyResultString := utils.CheckResourceAccessPolicy(*describeOutput.Policy)

				lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
				newProperties := resource.Properties.(string)[:lastBracketIndex] + "," + policyResultString + "}"

				out <- types.EnrichedResourceDescription{
					Identifier: resource.Identifier,
					TypeName:   resource.TypeName,
					Region:     resource.Region,
					Properties: newProperties,
					AccountId:  resource.AccountId,
				}
			}
		}
		close(out)
	}()
	return out
}
