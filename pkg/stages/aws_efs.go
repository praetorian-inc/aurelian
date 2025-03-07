package stages

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	options "github.com/praetorian-inc/nebula/pkg/links/opts"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

func AwsEfsFileSystemCheckResourcePolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "EFSFileSystemCheckResourcePolicy")
	logger.Info("Checking EFS File Systems resource access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			efsClient := efs.NewFromConfig(config)

			policyInput := &efs.DescribeFileSystemPolicyInput{
				FileSystemId: aws.String(resource.Identifier),
			}
			policyOutput, err := efsClient.DescribeFileSystemPolicy(ctx, policyInput)
			if err != nil {
				logger.Debug("Could not get EFS File Systems resource access policy for " + resource.Identifier + ", error: " + err.Error())
				if strings.Contains(err.Error(), "PolicyNotFound") {
					lastBracketIndex := strings.LastIndex(resource.Properties.(string), "}")
					newProperties := resource.Properties.(string)[:lastBracketIndex] + ",\"AccessPolicy\":\"Default (all users with network access can mount)\"}"

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
