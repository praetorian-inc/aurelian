package stages

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	options "github.com/praetorian-inc/nebula/pkg/links/opts"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

// AwsKmsKeyCheckResourcePolicy checks the resource policy of a KMS key
func AwsKmsKeyCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "KMSKeyCheckResourcePolicy")
	logger.Info("Checking KMS key resource access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			kmsClient := kms.NewFromConfig(config)

			policyInput := &kms.GetKeyPolicyInput{
				KeyId: aws.String(resource.Identifier),
			}
			policyOutput, err := kmsClient.GetKeyPolicy(ctx, policyInput)
			if err != nil {
				logger.Debug("Could not get KMS key resource access policy for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				policyResultString := utils.CheckResourceAccessPolicy(*policyOutput.Policy)

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

// AwsKmsKeyCheckGrants checks the grants of a KMS key
func AwsKmsKeyCheckGrants(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "KMSKeyCheckGrants")
	logger.Info("Checking KMS key grants")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			kmsClient := kms.NewFromConfig(config)

			policyInput := &kms.ListGrantsInput{
				KeyId: aws.String(resource.Identifier),
			}
			for {
				policyOutput, err := kmsClient.ListGrants(ctx, policyInput)
				if err != nil {
					logger.Debug("Could not get KMS key grants for " + resource.Identifier + ", error: " + err.Error())
					out <- resource
					break
				}

				var grantees []string
				for _, grant := range policyOutput.Grants {
					if strings.Contains(*grant.GranteePrincipal, "*") || strings.Contains(*grant.GranteePrincipal, "root") {
						grantees = append(grantees, *grant.GranteePrincipal)
					}
				}

				if len(grantees) == 0 {
					out <- resource
					break
				}

				granteesJson, err := json.Marshal(grantees)
				if err != nil {
					logger.Error("Could not marshal grantees")
					continue
				}

				lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
				newProperties := resource.Properties.(string)[:lastBracketIndex] + ",\"Grantees\":" + string(granteesJson) + "}"

				out <- types.EnrichedResourceDescription{
					Identifier: resource.Identifier,
					TypeName:   resource.TypeName,
					Region:     resource.Region,
					Properties: newProperties,
					AccountId:  resource.AccountId,
				}

				if policyOutput.NextMarker == nil {
					break
				}
				policyInput.Marker = policyOutput.NextMarker
			}
		}
		close(out)
	}()
	return out
}
