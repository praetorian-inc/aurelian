package general

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

type SupportsResourceTypes interface {
	SupportedResourceTypes() []string
}

// ResourceTypePreprocessor expands "all" into specific resource types
type ResourceTypePreprocessor struct {
	*plugin.BaseLink
	class SupportsResourceTypes
}

func NewResourceTypePreprocessor(class SupportsResourceTypes, args map[string]any) *ResourceTypePreprocessor {
	return &ResourceTypePreprocessor{
		BaseLink: plugin.NewBaseLink("resource-type-preprocessor", args),
		class:    class,
	}
}

func (p *ResourceTypePreprocessor) Process(ctx context.Context, input any) ([]any, error) {
	inputStr, ok := input.(string)
	if !ok {
		return nil, fmt.Errorf("expected string input, got %T", input)
	}

	var resourceTypes []string
	if strings.ToLower(inputStr) == "all" {
		resourceTypes = p.class.SupportedResourceTypes()
	} else {
		resourceTypes = []string{inputStr}
	}

	outputs := make([]any, len(resourceTypes))
	for i, rt := range resourceTypes {
		outputs[i] = rt
	}

	return outputs, nil
}

func (p *ResourceTypePreprocessor) Parameters() []plugin.Parameter {
	return nil
}

// SingleResourcePreprocessor converts ARN string to EnrichedResourceDescription
type SingleResourcePreprocessor struct {
	*plugin.BaseLink
}

func NewSingleResourcePreprocessor(args map[string]any) *SingleResourcePreprocessor {
	return &SingleResourcePreprocessor{
		BaseLink: plugin.NewBaseLink("single-resource-preprocessor", args),
	}
}

func (p *SingleResourcePreprocessor) Process(ctx context.Context, input any) ([]any, error) {
	inputStr, ok := input.(string)
	if !ok {
		return nil, fmt.Errorf("expected string input, got %T", input)
	}

	erd, err := types.NewEnrichedResourceDescriptionFromArn(inputStr)
	if err != nil {
		return nil, err
	}

	return []any{erd}, nil
}

func (p *SingleResourcePreprocessor) Parameters() []plugin.Parameter {
	return nil
}

// AzureSingleResourcePreprocessor passes through CloudResource
type AzureSingleResourcePreprocessor struct {
	*plugin.BaseLink
}

func NewAzureSingleResourcePreprocessor(args map[string]any) *AzureSingleResourcePreprocessor {
	return &AzureSingleResourcePreprocessor{
		BaseLink: plugin.NewBaseLink("azure-single-resource-preprocessor", args),
	}
}

func (p *AzureSingleResourcePreprocessor) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(*output.CloudResource)
	if !ok {
		return nil, fmt.Errorf("expected *output.CloudResource input, got %T", input)
	}

	return []any{resource}, nil
}

func (p *AzureSingleResourcePreprocessor) Parameters() []plugin.Parameter {
	return nil
}

// AzureResourceIDPreprocessor converts Azure resource ID string to CloudResource
type AzureResourceIDPreprocessor struct {
	*plugin.BaseLink
}

func NewAzureResourceIDPreprocessor(args map[string]any) *AzureResourceIDPreprocessor {
	return &AzureResourceIDPreprocessor{
		BaseLink: plugin.NewBaseLink("azure-resource-id-preprocessor", args),
	}
}

func (p *AzureResourceIDPreprocessor) Process(ctx context.Context, input any) ([]any, error) {
	inputStr, ok := input.(string)
	if !ok {
		return nil, fmt.Errorf("expected string input, got %T", input)
	}

	// The Azure resource ID format is: /subscriptions/{sub}/resourceGroups/{rg}/providers/{type}/{name}
	// We need to parse this to extract subscription, type, etc.
	parts := strings.Split(inputStr, "/")
	if len(parts) < 9 || parts[1] != "subscriptions" || parts[3] != "resourceGroups" || parts[5] != "providers" {
		return nil, fmt.Errorf("invalid Azure resource ID format: %s", inputStr)
	}

	subscriptionID := parts[2]
	resourceType := strings.Join(parts[6:len(parts)-1], "/")

	// Create a basic CloudResource with the resource ID
	azureResource := output.CloudResource{
		Platform:     "azure",
		ResourceType: resourceType,
		ResourceID:   inputStr,
		AccountRef:   subscriptionID,
		Properties: map[string]any{
			"resourceId": inputStr,
		},
	}

	return []any{&azureResource}, nil
}

func (p *AzureResourceIDPreprocessor) Parameters() []plugin.Parameter {
	return nil
}
