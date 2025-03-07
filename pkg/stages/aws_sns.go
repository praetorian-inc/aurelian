package stages

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	options "github.com/praetorian-inc/nebula/pkg/links/opts"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

// AwsSnsTopicCheckResourcePolicy checks the resource policy of an SNS topic
func AwsSnsTopicCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "SNSTopicCheckResourcePolicy")
	logger.Info("Checking SNS topic access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			snsClient := sns.NewFromConfig(config)

			attributeInput := &sns.GetTopicAttributesInput{
				TopicArn: aws.String(resource.Identifier),
			}
			attributeOutput, err := snsClient.GetTopicAttributes(ctx, attributeInput)
			if err != nil {
				logger.Debug("Could not getSNS topic access policy for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			}

			policyString, ok := attributeOutput.Attributes["Policy"]
			if !ok {
				logger.Debug("Could not find policy attribute for " + resource.Identifier)
				out <- resource
				continue
			} else {
				policyResultString := utils.CheckResourceAccessPolicy(policyString)

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
