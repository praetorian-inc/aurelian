package stages

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/ecrpublic"
	ecrpublictype "github.com/aws/aws-sdk-go-v2/service/ecrpublic/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/docker/docker/api/types/registry"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	options "github.com/praetorian-inc/nebula/pkg/links/opts"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

// AwsEcrLoginStage logs into Amazon ECR repositories.
func AwsEcrLoginStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan ImageContext {
	logger := logs.NewStageLogger(ctx, opts, "ECRLoginStage")
	out := make(chan ImageContext)

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
			jwt := strings.Split(string(parsed), ":")[1]

			account, err := helpers.GetAccountId(config)
			if err != nil {
				logger.Error(err.Error())
				continue
			}

			out <- ImageContext{
				AuthConfig: registry.AuthConfig{
					Username:      "AWS",
					Password:      string(jwt),
					ServerAddress: fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com", account, region),
				},
				Image: uri,
			}
		}
	}()
	return out
}

// AwsEcrPublicLoginStage logs into Amazon ECR repositories.
func AwsEcrPublicLoginStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan ImageContext {
	logger := logs.NewStageLogger(ctx, opts, "ECRLoginStage")
	out := make(chan ImageContext)

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

			client := ecrpublic.NewFromConfig(config)
			input := &ecrpublic.GetAuthorizationTokenInput{}
			tokenOutput, err := client.GetAuthorizationToken(ctx, input)
			if err != nil {
				logger.Error(err.Error())
				continue
			}

			token := tokenOutput.AuthorizationData.AuthorizationToken
			parsed, err := base64.StdEncoding.DecodeString(*token)
			if err != nil {
				logger.Error(err.Error())
				continue
			}

			out <- ImageContext{
				AuthConfig: registry.AuthConfig{
					Username:      "AWS",
					Password:      string(parsed),
					ServerAddress: fmt.Sprintf("public.ecr.aws"),
				},
				Image: uri,
			}
		}
	}()
	return out
}

// AwsEcrListImages lists images in Amazon ECR repositories, returning only the latest version.
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
			if resource.TypeName != "AWS::ECR::Repository" {
				logger.Debug("Skipping non-ECR resource", slog.String("identifier", resource.Identifier))
				continue
			}

			config, err := helpers.GetAWSCfg(resource.Region, profile, opts)
			if err != nil {
				logger.Error(err.Error())
				continue
			}

			privateClient := ecr.NewFromConfig(config)
			input := &ecr.DescribeImagesInput{
				RepositoryName: &resource.Identifier,
				MaxResults:     aws.Int32(1000),
			}

			// Get registry info for this account/region
			registryDomain := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com", resource.AccountId, resource.Region)

			var latest *ecrtypes.ImageDetail
			for {
				result, err := privateClient.DescribeImages(ctx, input)
				if err != nil {
					logger.Error("Error describing private images for %s: %v", resource.Identifier, err)
					break
				}

				// Compare images in this page to find latest
				for _, image := range result.ImageDetails {
					if latest == nil || image.ImagePushedAt.After(*latest.ImagePushedAt) {
						latest = &image
					}
				}

				if result.NextToken == nil {
					break
				}
				input.NextToken = result.NextToken
			}

			if latest != nil {
				if latest.ImageTags != nil && len(latest.ImageTags) > 0 {
					uri := fmt.Sprintf("%s/%s:%s", registryDomain, resource.Identifier, latest.ImageTags[0])
					out <- uri
				} else if latest.ImageDigest != nil {
					uri := fmt.Sprintf("%s/%s@%s", registryDomain, resource.Identifier, *latest.ImageDigest)
					out <- uri
				}
			}
		}
	}()

	return out
}

// AwsEcrPublicListLatestImages looks up details about a public ECR image and returns the latest version URL
func AwsEcrPublicListLatestImages(ctx context.Context, opts []*types.Option, in <-chan types.EnrichedResourceDescription) <-chan string {
	logger := logs.NewStageLogger(ctx, opts, "AwsEcrPublicListLatestImages")
	out := make(chan string)

	go func() {
		defer close(out)
		for resource := range in {
			if resource.TypeName != "AWS::ECR::PublicRepository" {
				logger.Debug("Skipping non-public ECR resource", slog.String("identifier", resource.Identifier))
				continue
			}

			config, err := helpers.GetAWSCfg("us-east-1", options.GetOptionByName(options.AwsProfileOpt.Name, opts).Value, opts)
			if err != nil {
				logger.Error("Could not set up client config, error: " + err.Error())
				continue
			}

			ecrPublicClient := ecrpublic.NewFromConfig(config)

			// First get repository info to get the registry alias
			descInput := &ecrpublic.DescribeRepositoriesInput{
				RepositoryNames: []string{resource.Identifier},
			}

			descResp, err := ecrPublicClient.DescribeRepositories(ctx, descInput)
			if err != nil {
				logger.Error("Could not describe repository " + resource.Identifier + ", error: " + err.Error())
				continue
			}

			if len(descResp.Repositories) == 0 {
				logger.Error("Repository not found: " + resource.Identifier)
				continue
			}

			registryAlias := *descResp.Repositories[0].RepositoryUri
			registryAlias = strings.TrimSuffix(strings.TrimPrefix(registryAlias, "public.ecr.aws/"), "/"+resource.Identifier)

			input := &ecrpublic.DescribeImagesInput{
				RepositoryName: aws.String(resource.Identifier),
				MaxResults:     aws.Int32(1000),
			}

			var latest *ecrpublictype.ImageDetail
			for {
				result, err := ecrPublicClient.DescribeImages(ctx, input)
				if err != nil {
					logger.Error("Could not get public image details for " + resource.Identifier + ", error: " + err.Error())
					break
				}

				// Compare images in this page to find latest
				for _, image := range result.ImageDetails {
					if latest == nil || image.ImagePushedAt.After(*latest.ImagePushedAt) {
						latest = &image
					}
				}

				// Check for more pages
				if result.NextToken == nil {
					break
				}
				input.NextToken = result.NextToken
			}

			if latest != nil && len(latest.ImageTags) > 0 {
				// Format: public.ecr.aws/registry-alias/repository:tag
				imageURL := fmt.Sprintf("public.ecr.aws/%s/%s:%s",
					registryAlias,
					resource.Identifier,
					latest.ImageTags[0])
				out <- imageURL
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
