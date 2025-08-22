package general

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	jlinks "github.com/praetorian-inc/janus-framework/pkg/links"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

type SupportsResourceTypes interface {
	SupportedResourceTypes() []model.CloudResourceType
}

func PreprocessResourceTypes(class SupportsResourceTypes) func(chain.Link, string) error {
	processor := func(self chain.Link, input string) error {
		resourceTypes := []model.CloudResourceType{model.CloudResourceType(input)}

		if strings.ToLower(input) == "all" {
			resourceTypes = class.SupportedResourceTypes()
		}

		for _, resourceType := range resourceTypes {
			self.Send(resourceType)
		}

		return nil
	}

	return processor
}

func NewResourceTypePreprocessor(class SupportsResourceTypes) func(...cfg.Config) chain.Link {
	preprocessor := PreprocessResourceTypes(class)
	return jlinks.ConstructAdHocLink(preprocessor)
}

// NewSingleResourcePreprocessor returns a link that accepts a string (ARN), constructs an EnrichedResourceDescription, and sends it.
func NewSingleResourcePreprocessor() func(...cfg.Config) chain.Link {
	preprocessor := func(self chain.Link, input string) error {
		erd, err := types.NewEnrichedResourceDescriptionFromArn(input)
		if err != nil {
			return err
		}
		self.Send(erd)
		return nil
	}
	return jlinks.ConstructAdHocLink(preprocessor)
}

// NewAzureSingleResourcePreprocessor returns a link that accepts an AzureResource and sends it for processing.
// This is used for processing individual Azure resources from list-all-resources output.
func NewAzureSingleResourcePreprocessor() func(...cfg.Config) chain.Link {
	preprocessor := func(self chain.Link, input *model.AzureResource) error {
		self.Send(input)
		return nil
	}
	return jlinks.ConstructAdHocLink(preprocessor)
}

// NewAzureResourceIDPreprocessor returns a link that accepts an Azure resource ID string,
// constructs an AzureResource object, and sends it for processing.
func NewAzureResourceIDPreprocessor() func(...cfg.Config) chain.Link {
	preprocessor := func(self chain.Link, input string) error {
		// The Azure resource ID format is: /subscriptions/{sub}/resourceGroups/{rg}/providers/{type}/{name}
		// We need to parse this to extract subscription, type, etc.
		parts := strings.Split(input, "/")
		if len(parts) < 9 || parts[1] != "subscriptions" || parts[3] != "resourceGroups" || parts[5] != "providers" {
			return fmt.Errorf("invalid Azure resource ID format: %s", input)
		}

		subscriptionID := parts[2]
		resourceType := strings.Join(parts[6:len(parts)-1], "/")

		// Create a basic AzureResource with the resource ID
		azureResource, err := model.NewAzureResource(
			input, // Use full resource ID as the name
			subscriptionID,
			model.CloudResourceType(resourceType),
			map[string]any{
				"resourceId": input,
			},
		)
		if err != nil {
			return fmt.Errorf("failed to create AzureResource from ID: %w", err)
		}

		self.Send(&azureResource)
		return nil
	}
	return jlinks.ConstructAdHocLink(preprocessor)
}
