package stages

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecrpublic"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

// AwsEcrLoginStage logs into Amazon ECR repositories.
func AwsEcrLoginStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan string {
	logger := logs.NewStageLogger(ctx, opts, "ECRLoginStage")
	out := make(chan string)

	go func() {
		defer close(out)
		for uri := range in {
			// Skip if user and password are already set
			if options.GetOptionByName(options.DockerUserOpt.Name, opts).Value != "" || options.GetOptionByName(options.DockerPasswordOpt.Name, opts).Value != "" {
				continue
			}

			region, err := DockerExtractRegion(uri)
			if err != nil {
				logger.Error(err.Error())
				continue
			}

			config, err := helpers.GetAWSCfg(region, options.GetOptionByName("profile", opts).Value, opts)
			if err != nil {
				logger.Error(err.Error())
				continue
			}

			client := ecr.NewFromConfig(config)
			input := &ecr.GetAuthorizationTokenInput{}
			tokenOutput, err := client.GetAuthorizationToken(ctx, input)
			if err != nil {
				logger.Error(err.Error())
				continue
			}

			token := tokenOutput.AuthorizationData[0].AuthorizationToken
			parsed, err := base64.StdEncoding.DecodeString(*token)
			if err != nil {
				logger.Error(err.Error())
				continue
			}
			user := options.GetOptionByName(options.DockerUserOpt.Name, opts)
			user.Value = strings.Split(string(parsed), ":")[0]

			password := options.GetOptionByName(options.DockerPasswordOpt.Name, opts)
			password.Value = strings.Split(string(parsed), ":")[1]

			out <- uri
		}
	}()
	return out
}

// AwsEcrListImages lists the images in both public and private Amazon ECR repositories.
// It takes a context, a slice of options, and a channel of EnrichedResourceDescription as input,
// and returns a channel of image URIs as output.
func AwsEcrListImages(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan string {
	logger := logs.NewStageLogger(ctx, opts, "ListECRImages")
	out := make(chan string)
	profile := options.GetOptionByName("profile", opts).Value

	go func() {
		defer close(out)
		for resource := range in {
			// Skip if invalid resource description
			if resource.Properties == nil {
				logger.Debug("Skipping resource with no properties", slog.String("identifier", resource.Identifier))
				continue
			}

			// Handle public repositories (only in us-east-1)
			if resource.TypeName == "AWS::ECR::PublicRepository" {
				config, err := helpers.GetAWSCfg("us-east-1", profile, opts)
				if err != nil {
					logger.Error(err.Error())
					continue
				}

				publicClient := ecrpublic.NewFromConfig(config)
				input := &ecrpublic.DescribeImagesInput{
					RepositoryName: &resource.Identifier,
				}

				// Get public registry domain
				registryDomain := "public.ecr.aws"

				for {
					result, err := publicClient.DescribeImages(ctx, input)
					if err != nil {
						logger.Error("Error describing public images for %s: %v", resource.Identifier, err)
						break
					}

					for _, image := range result.ImageDetails {
						if image.ImageTags != nil && len(image.ImageTags) > 0 {
							for _, tag := range image.ImageTags {
								uri := fmt.Sprintf("%s/%s:%s", registryDomain, resource.Identifier, tag)
								out <- uri
							}
						} else if image.ImageDigest != nil {
							uri := fmt.Sprintf("%s/%s@%s", registryDomain, resource.Identifier, *image.ImageDigest)
							out <- uri
						}
					}

					if result.NextToken == nil {
						break
					}
					input.NextToken = result.NextToken
				}
			} else { // Handle private repositories
				config, err := helpers.GetAWSCfg(resource.Region, profile, opts)
				if err != nil {
					logger.Error(err.Error())
					continue
				}

				privateClient := ecr.NewFromConfig(config)
				input := &ecr.DescribeImagesInput{
					RepositoryName: &resource.Identifier,
				}

				// Get registry info for this account/region
				registryDomain := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com", resource.AccountId, resource.Region)

				for {
					result, err := privateClient.DescribeImages(ctx, input)
					if err != nil {
						logger.Error("Error describing private images for %s: %v", resource.Identifier, err)
						break
					}

					for _, image := range result.ImageDetails {
						fmt.Println(image)
						if image.ImageTags != nil && len(image.ImageTags) > 0 {
							for _, tag := range image.ImageTags {
								uri := fmt.Sprintf("%s/%s:%s", registryDomain, resource.Identifier, tag)
								out <- uri
							}
						} else if image.ImageDigest != nil {
							uri := fmt.Sprintf("%s/%s@%s", registryDomain, resource.Identifier, *image.ImageDigest)
							out <- uri
						}
					}

					if result.NextToken == nil {
						break
					}
					input.NextToken = result.NextToken
				}
			}
		}
	}()

	return out
}

// AwsEcrCheckPublicRepoPolicy checks the access policy of public Amazon ECR repositories.
func AwsEcrCheckRepoPolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "ECRCheckRepoPolicy")
	logger.Info("Checking ECR repository access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			ecrClient := ecr.NewFromConfig(config)

			policyInput := &ecr.GetRepositoryPolicyInput{
				RepositoryName: aws.String(resource.Identifier),
			}
			policyOutput, err := ecrClient.GetRepositoryPolicy(ctx, policyInput)
			if err != nil {
				logger.Debug("Could not get ECR repository access policy for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				policyResultString := utils.CheckResourceAccessPolicy(*policyOutput.PolicyText)

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

// AwsEcrCheckPublicRepoPolicy checks the access policy for public Amazon ECR repositories.
func AwsEcrCheckPublicRepoPolicy(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan types.EnrichedResourceDescription {
	logger := logs.NewStageLogger(ctx, opts, "ECRCheckPublicRepoPolicy")
	logger.Info("Checking ECR public repository access policies")
	out := make(chan types.EnrichedResourceDescription)
	go func() {
		for resource := range in {
			config, err := helpers.GetAWSCfg(resource.Region, options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}
			ecrPublicClient := ecrpublic.NewFromConfig(config)

			policyInput := &ecrpublic.GetRepositoryPolicyInput{
				RepositoryName: aws.String(resource.Identifier),
			}
			policyOutput, err := ecrPublicClient.GetRepositoryPolicy(ctx, policyInput)
			if err != nil {
				logger.Debug("Could not get ECR public repository access policy for " + resource.Identifier + ", error: " + err.Error())
				out <- resource
			} else {
				policyResultString := utils.CheckResourceAccessPolicy(*policyOutput.PolicyText)

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
