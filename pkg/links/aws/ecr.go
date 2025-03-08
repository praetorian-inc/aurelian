package aws

import (
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/janus/pkg/util"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AWSECRListImages struct {
	*AwsReconLink
}

func NewAWSECRListImages(configs ...cfg.Config) chain.Link {
	r := &AWSECRListImages{}
	r.AwsReconLink = NewAwsReconLink(r, configs...)
	return r
}

func (r *AWSECRListImages) Process(resource *types.EnrichedResourceDescription) error {
	if resource.Properties == nil {
		slog.Debug("Skipping resource with no properties", "identifier", resource.Identifier)
		return nil
	}

	if resource.TypeName != "AWS::ECR::Repository" {
		slog.Debug("Skipping non-ECR resource", "identifier", resource.Identifier)
		return nil
	}

	config, err := util.GetAWSConfig(resource.Region, "repositoryName")
	if err != nil {
		slog.Error("Failed to get AWS config", "error", err)
		return nil
	}

	ecrClient := ecr.NewFromConfig(config)
	input := &ecr.DescribeImagesInput{
		RepositoryName: &resource.Identifier,
		MaxResults:     aws.Int32(1000),
	}

	ecrRegistry := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com", resource.AccountId, resource.Region)
	var latest *ecrtypes.ImageDetail

	for {
		result, err := ecrClient.DescribeImages(r.Context(), input)
		if err != nil {
			slog.Error("Failed to describe images", "error", err)
			return nil
		}

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

	if latest == nil {
		slog.Debug("No images found for repository", "identifier", resource.Identifier)
		return nil
	}

	var uri string
	if latest.ImageTags != nil && len(latest.ImageTags) > 0 {
		uri = fmt.Sprintf("%s/%s:%s", ecrRegistry, resource.Identifier, latest.ImageTags[0])
	} else if latest.ImageDigest != nil {
		uri = fmt.Sprintf("%s/%s@%s", ecrRegistry, resource.Identifier, *latest.ImageDigest)
	}

	r.Send(uri)

	return nil
}
