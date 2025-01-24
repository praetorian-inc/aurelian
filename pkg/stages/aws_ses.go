package stages

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

// AwsSesIdentityCheckResourcePolicy checks the resource policy of an SES email identity
func AwsSesIdentityCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "SESIdentityCheckResourcePolicy")
	logger.Info("Checking SES email identity resource access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			sesClient := ses.NewFromConfig(config)

			policyInput := &ses.ListIdentityPoliciesInput{
				Identity: aws.String(resource.Identifier),
			}
			policyOutput, err := sesClient.ListIdentityPolicies(ctx, policyInput)
			if err != nil {
				logger.Debug("Could not get SES email identity resource access policies for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				var policyResultStrings []string
				for i := 0; i < len(policyOutput.PolicyNames); i += 20 {
					end := i + 20
					if end > len(policyOutput.PolicyNames) {
						end = len(policyOutput.PolicyNames)
					}
					policyNamesChunk := policyOutput.PolicyNames[i:end]

					policyInput := &ses.GetIdentityPoliciesInput{
						Identity:    aws.String(resource.Identifier),
						PolicyNames: policyNamesChunk,
					}
					policyDetails, err := sesClient.GetIdentityPolicies(ctx, policyInput)
					if err != nil {
						logger.Debug("Could not get SES email identity policy details for " + resource.Identifier + ", error: " + err.Error())
						continue
					}

					for _, policyDocument := range policyDetails.Policies {
						policyResultString := utils.CheckResourceAccessPolicy(policyDocument)
						start := strings.Index(policyResultString, "[")
						end := strings.LastIndex(policyResultString, "]")
						if start != -1 && end != -1 {
							policyResultStrings = append(policyResultStrings, policyResultString[start+1:end])
						}
					}
				}

				if len(policyResultStrings) > 0 {
					lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
					newProperties := resource.Properties.(string)[:lastBracketIndex] + ",\"AccessPolicy\":{\"Statement\":[" + strings.Join(policyResultStrings, ",") + "]}}"

					out <- types.EnrichedResourceDescription{
						Identifier: resource.Identifier,
						TypeName:   resource.TypeName,
						Region:     resource.Region,
						Properties: newProperties,
						AccountId:  resource.AccountId,
					}
				} else {
					out <- resource
				}
			}
		}
		close(out)
	}()
	return out
}
