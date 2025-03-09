package ecr

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ecrpublic"
	ecrpublictypes "github.com/aws/aws-sdk-go-v2/service/ecrpublic/types"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/janus/pkg/util"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AWSECRListPublicImages struct {
	*base.AwsReconLink
}

func NewAWSECRListPublicImages(configs ...cfg.Config) chain.Link {
	ep := &AWSECRListPublicImages{}
	ep.AwsReconLink = base.NewAwsReconLink(ep, configs...)
	return ep
}

func (ep *AWSECRListPublicImages) Process(resource *types.EnrichedResourceDescription) error {
	if resource.TypeName != "AWS::ECR::PublicRepository" {
		slog.Debug("Skipping non-ECR resource", "identifier", resource.Identifier, "resource", resource)
		return nil
	}

	config, err := util.GetAWSConfig(resource.Region, ep.Profile)
	if err != nil {
		slog.Error("Failed to get AWS config", "error", err)
		return nil
	}

	ecrClient := ecrpublic.NewFromConfig(config)

	repositoryURI, err := ep.getRepositoryURI(ecrClient, resource)
	if err != nil {
		slog.Debug("Failed to get repository URI", "identifier", resource.Identifier, "error", err)
		return nil
	}

	imageURL, err := ep.getLatestImage(ecrClient, resource, repositoryURI)
	if err != nil {
		slog.Debug("Failed to get latest image", "URI", repositoryURI, "error", err)
		return nil
	}

	return ep.Send(imageURL)
}

func (ep *AWSECRListPublicImages) getRepositoryURI(ecrClient *ecrpublic.Client, resource *types.EnrichedResourceDescription) (string, error) {
	describeReposInput := &ecrpublic.DescribeRepositoriesInput{
		RepositoryNames: []string{resource.Identifier},
	}

	descResp, err := ecrClient.DescribeRepositories(ep.Context(), describeReposInput)
	if err != nil {
		return "", fmt.Errorf("could not describe repository %s: %w", resource.Identifier, err)
	}

	if len(descResp.Repositories) == 0 {
		return "", fmt.Errorf("no repositories found: " + resource.Identifier)
	}

	repositoryURI := *descResp.Repositories[0].RepositoryUri

	return repositoryURI, nil
}

func (ep *AWSECRListPublicImages) getLatestImage(ecrClient *ecrpublic.Client, resource *types.EnrichedResourceDescription, repositoryURI string) (string, error) {
	registryAlias := strings.TrimPrefix(repositoryURI, "public.ecr.aws/")
	registryAlias = strings.TrimSuffix(registryAlias, "/"+resource.Identifier)

	describeImagesInput := &ecrpublic.DescribeImagesInput{
		RepositoryName: aws.String(resource.Identifier),
		MaxResults:     aws.Int32(1000),
	}

	var latest *ecrpublictypes.ImageDetail
	for {
		result, err := ecrClient.DescribeImages(ep.Context(), describeImagesInput)
		if err != nil {
			slog.Debug("Could not get public image details for "+resource.Identifier, "error", err)
			break
		}

		for _, image := range result.ImageDetails {
			if latest == nil || image.ImagePushedAt.After(*latest.ImagePushedAt) {
				latest = &image
			}
		}

		if result.NextToken == nil {
			break
		}

		describeImagesInput.NextToken = result.NextToken
	}

	imageURL := ""
	if latest != nil && len(latest.ImageTags) > 0 {
		imageURL = fmt.Sprintf("public.ecr.aws/%s/%s:%s",
			registryAlias,
			resource.Identifier,
			latest.ImageTags[0],
		)
	}

	return imageURL, nil
}
