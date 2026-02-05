package ecr

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/praetorian-inc/aurelian/internal/message"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

type AWSECRListImages struct {
	*base.NativeAWSLink
}

func NewAWSECRListImages(args map[string]any) *AWSECRListImages {
	return &AWSECRListImages{
		NativeAWSLink: base.NewNativeAWSLink("ecr-list-images", args),
	}
}

func (e *AWSECRListImages) Parameters() []plugin.Parameter {
	return base.StandardAWSParams()
}

func (e *AWSECRListImages) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(*types.EnrichedResourceDescription)
	if !ok {
		return nil, fmt.Errorf("expected *types.EnrichedResourceDescription, got %T", input)
	}

	if resource.Properties == nil {
		slog.Debug("Skipping resource with no properties", "identifier", resource.Identifier)
		return nil, nil
	}

	if resource.TypeName != "AWS::ECR::Repository" {
		slog.Debug("Skipping non-ECR resource", "identifier", resource.Identifier)
		return nil, nil
	}

	config, err := e.GetConfig(ctx, resource.Region)
	if err != nil {
		slog.Error("Failed to get AWS config", "error", err)
		return nil, nil
	}

	ecrClient := ecr.NewFromConfig(config)
	describeInput := &ecr.DescribeImagesInput{
		RepositoryName: &resource.Identifier,
		MaxResults:     aws.Int32(1000),
	}

	ecrRegistry := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com", resource.AccountId, resource.Region)
	var latest *ecrtypes.ImageDetail

	for {
		result, err := ecrClient.DescribeImages(ctx, describeInput)
		if err != nil {
			slog.Error("Failed to describe images", "error", err)
			return nil, nil
		}

		for _, image := range result.ImageDetails {
			if latest == nil || image.ImagePushedAt.After(*latest.ImagePushedAt) {
				latest = &image
			}
		}

		if result.NextToken == nil {
			break
		}

		describeInput.NextToken = result.NextToken
	}

	if latest == nil {
		slog.Debug("No images found for repository", "identifier", resource.Identifier)
		return nil, nil
	}

	var uri string
	if len(latest.ImageTags) > 0 {
		uri = fmt.Sprintf("%s/%s:%s", ecrRegistry, resource.Identifier, latest.ImageTags[0])
	} else if latest.ImageDigest != nil {
		uri = fmt.Sprintf("%s/%s@%s", ecrRegistry, resource.Identifier, *latest.ImageDigest)
	}

	message.Info("Processing image: %s", uri)
	return []any{uri}, nil
}
