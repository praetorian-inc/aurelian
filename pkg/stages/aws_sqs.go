package stages

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqsTypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	options "github.com/praetorian-inc/nebula/pkg/links/opts"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

// AwsSqsQueueCheckResourcePolicy checks the resource policy of an SQS queue
func AwsSqsQueueCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "SQSQueueCheckResourcePolicy")
	logger.Info("Checking SQS queue access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			sqsClient := sqs.NewFromConfig(config)

			attributeInput := &sqs.GetQueueAttributesInput{
				QueueUrl: aws.String(resource.Identifier),
				AttributeNames: []sqsTypes.QueueAttributeName{
					sqsTypes.QueueAttributeNamePolicy,
				},
			}
			attributeOutput, err := sqsClient.GetQueueAttributes(ctx, attributeInput)
			if err != nil {
				logger.Debug("Could not get SQS queue access policy for " + resource.Identifier + ", error: " + err.Error())
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
