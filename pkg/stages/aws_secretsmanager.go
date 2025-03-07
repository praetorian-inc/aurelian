package stages

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	options "github.com/praetorian-inc/nebula/pkg/links/opts"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

// AwsSecretCheckResourcePolicy checks the resource policy of a SecretsManager secret
func AwsSecretCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "SecretCheckResourcePolicy")
	logger.Info("Checking SecretsManager secret access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			smClient := secretsmanager.NewFromConfig(config)

			policyInput := &secretsmanager.GetResourcePolicyInput{
				SecretId: aws.String(resource.Identifier),
			}
			policyOutput, err := smClient.GetResourcePolicy(ctx, policyInput)
			if err != nil {
				logger.Debug("Could not get SecretsManager secret access policy for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else if policyOutput.ResourcePolicy == nil {
				logger.Debug("Could not get SecretsManager secret access policy for " + resource.Identifier + ", policy doesn't exist")
				out <- resource
			} else {
				policyResultString := utils.CheckResourceAccessPolicy(*policyOutput.ResourcePolicy)

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
