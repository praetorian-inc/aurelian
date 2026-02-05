package cloudformation

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

type AWSCloudFormationTemplates struct {
	*base.NativeAWSLink
}

func NewAWSCloudFormationTemplates(args map[string]any) *AWSCloudFormationTemplates {
	return &AWSCloudFormationTemplates{
		NativeAWSLink: base.NewNativeAWSLink("cloudformation", args),
	}
}

func (a *AWSCloudFormationTemplates) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(*types.EnrichedResourceDescription)
	if !ok {
		return nil, fmt.Errorf("expected *types.EnrichedResourceDescription, got %T", input)
	}

	config, err := a.GetConfig(ctx, resource.Region)
	if err != nil {
		slog.Debug("Failed to get AWS config for region", "region", resource.Region, "error", err)
		return a.Outputs(), nil
	}

	client := cloudformation.NewFromConfig(config)

	template, err := client.GetTemplate(ctx, &cloudformation.GetTemplateInput{
		StackName: &resource.Identifier,
	})

	if err != nil {
		slog.Debug("Failed to get template", "error", err)
		return a.Outputs(), nil
	}

	encoded := base64.StdEncoding.EncodeToString([]byte(*template.TemplateBody))

	a.Send(&types.NpInput{
		ContentBase64: encoded,
		Provenance: types.NpProvenance{
			Platform:     "aws",
			ResourceType: "AWS::CloudFormation::Template",
			ResourceID:   resource.Arn.String(),
		},
	})
	return a.Outputs(), nil
}
