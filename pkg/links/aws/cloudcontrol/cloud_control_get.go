package cloudcontrol

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

type CloudControlGet struct {
	*base.NativeAWSLink
}

func NewCloudControlGet(args map[string]any) *CloudControlGet {
	return &CloudControlGet{
		NativeAWSLink: base.NewNativeAWSLink("CloudControlGet", args),
	}
}

func (c *CloudControlGet) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(*types.EnrichedResourceDescription)
	if !ok {
		slog.Debug("Unexpected input type for CloudControlGet", "input", input)
		return nil, nil
	}

	config, err := c.GetConfig(ctx, resource.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS config: %w", err)
	}

	client := cloudcontrol.NewFromConfig(config)

	getInput := &cloudcontrol.GetResourceInput{
		Identifier: &resource.Identifier,
		TypeName:   &resource.TypeName,
	}

	output, err := client.GetResource(context.TODO(), getInput)
	if err != nil {
		// Handle ResourceNotFoundException gracefully - resource may have been deleted between discovery and processing
		if strings.Contains(err.Error(), "ResourceNotFoundException") || strings.Contains(err.Error(), "NotFound") {
			slog.Debug("Resource not found, skipping",
				"resource_id", resource.Identifier,
				"resource_type", resource.TypeName,
				"arn", resource.Arn.String())
			return nil, nil
		}
		slog.Error("Failed to get resource", "arn", resource.Arn.String(), "error", err)
		return nil, err
	}

	var properties map[string]any
	if err := json.Unmarshal([]byte(*output.ResourceDescription.Properties), &properties); err != nil {
		return nil, fmt.Errorf("failed to unmarshal properties: %w", err)
	}

	enriched := &types.EnrichedResourceDescription{
		Region:     resource.Region,
		TypeName:   *getInput.TypeName,
		Identifier: *getInput.Identifier,
		Properties: properties,
		AccountId:  resource.AccountId,
		Arn:        resource.Arn,
	}

	c.Send(enriched)
	return c.Outputs(), nil
}
