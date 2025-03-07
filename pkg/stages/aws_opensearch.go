package stages

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

// AwsOpenSearchDomainCheckResourcePolicy checks the resource policy of an OpenSearch domain
func AwsOpenSearchDomainCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "OSSDomainCheckResourcePolicy")
	logger.Info("Checking OpenSearch domain resource access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			ossClient := opensearch.NewFromConfig(config)

			policyInput := &opensearch.DescribeDomainConfigInput{
				DomainName: aws.String(resource.Identifier),
			}
			policyOutput, err := ossClient.DescribeDomainConfig(ctx, policyInput)
			if err != nil {
				logger.Debug("Could not get OpenSearch domain resource access policy for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else if policyOutput.DomainConfig == nil || policyOutput.DomainConfig.AccessPolicies == nil || policyOutput.DomainConfig.AccessPolicies.Options == nil {
				logger.Debug("Could not get OpenSearch domain resource access policy for " + resource.Identifier + ", no policy exists")
				out <- resource
			} else {
				policyResultString := utils.CheckResourceAccessPolicy(*policyOutput.DomainConfig.AccessPolicies.Options)

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
