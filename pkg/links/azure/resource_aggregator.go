package azure

import (
	"context"
	"fmt"
	"maps"
	"path/filepath"
	"strconv"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/links/azure/base"
	"github.com/praetorian-inc/aurelian/pkg/links/options"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/outputters"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// AzureResourceAggregatorLink collects Azure resources and outputs them with filename generation
type AzureResourceAggregatorLink struct {
	*base.NativeAzureLink
	resources       []output.CloudResource
	resourceDetails []*types.AzureResourceDetails
	currentDetails  *types.AzureResourceDetails
}

func NewAzureResourceAggregatorLink(args map[string]any) *AzureResourceAggregatorLink {
	return &AzureResourceAggregatorLink{
		NativeAzureLink: base.NewNativeAzureLink("azure-resource-aggregator", args),
		resources:       make([]output.CloudResource, 0),
		resourceDetails: make([]*types.AzureResourceDetails, 0),
	}
}

func (l *AzureResourceAggregatorLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		options.OutputDir(),
		plugin.NewParam[string]("filename", "Base filename for output"),
	}
}

func (l *AzureResourceAggregatorLink) Process(ctx context.Context, input any) ([]any, error) {
	switch v := input.(type) {
	case output.CloudResource:
		l.resources = append(l.resources, v)
		l.Logger().Debug("Aggregated CloudResource", "type", v.ResourceType, "id", v.ResourceID, "total", len(l.resources))

	case *types.AzureResourceDetails:
		l.resourceDetails = append(l.resourceDetails, v)
		l.currentDetails = v // Keep track of the latest details for metadata
		l.Logger().Debug("Aggregated AzureResourceDetails", "subscription", v.SubscriptionID, "count", len(v.Resources))

	default:
		l.Logger().Debug("Received unknown input type", "type", fmt.Sprintf("%T", input))
	}

	return l.Outputs(), nil
}

func (l *AzureResourceAggregatorLink) Complete() error {
	filename := l.ArgString("filename", "")

	l.Logger().Info("Aggregation complete", "azure_resources", len(l.resources), "resource_details", len(l.resourceDetails))

	// Use resource details for generating outputs if available
	if len(l.resourceDetails) > 0 {
		for _, resourceDetails := range l.resourceDetails {
			l.generateOutput(resourceDetails, filename)
		}
	} else if len(l.resources) > 0 {
		// If we only have AzureResource objects, convert them for output
		l.generateOutputFromAzureResources(filename)
	}

	return nil
}

func (l *AzureResourceAggregatorLink) generateOutput(resourceDetails *types.AzureResourceDetails, baseFilename string) {
	// Get output directory
	outputDir := l.ArgString("output", "")

	// Generate filename if not provided
	if baseFilename == "" {
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		baseFilename = fmt.Sprintf("list-all-%s-%s", resourceDetails.SubscriptionID, timestamp)
	} else {
		baseFilename = baseFilename + "-" + resourceDetails.SubscriptionID
	}

	l.Logger().Info("Generated filename", "filename", baseFilename, "subscription", resourceDetails.SubscriptionID, "output_dir", outputDir)

	// Convert and send individual CloudResource objects - let the outputter aggregate them
	for i, resource := range resourceDetails.Resources {
		props := make(map[string]any)
		maps.Copy(props, resource.Properties)

		props["name"] = resource.Name
		props["tags"] = resource.Tags
		props["location"] = resource.Location
		props["resourceGroup"] = resource.ResourceGroup

		cloudResource := &output.CloudResource{
			Platform:     "azure",
			ResourceType: resource.Type,
			ResourceID:   resource.ID,
			AccountRef:   resourceDetails.SubscriptionID,
			Region:       resource.Location,
			DisplayName:  resource.Name,
			Properties:   props,
		}

		// For the first resource, set the filename. For subsequent resources, just send the data
		if i == 0 {
			// Create full path with output directory
			jsonFilePath := filepath.Join(outputDir, baseFilename+".json")
			jsonOutputData := outputters.NewNamedOutputData(cloudResource, jsonFilePath)
			l.Send(jsonOutputData)
		} else {
			// Send subsequent resources without filename - they'll be added to the same output array
			l.Send(cloudResource)
		}
	}
}

func (l *AzureResourceAggregatorLink) generateOutputFromAzureResources(baseFilename string) {
	// Get output directory
	outputDir := l.ArgString("output", "")

	if l.currentDetails == nil {
		// Generate basic filename if we don't have details
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		if baseFilename == "" {
			baseFilename = fmt.Sprintf("list-all-azure-%s", timestamp)
		}
	} else {
		if baseFilename == "" {
			timestamp := strconv.FormatInt(time.Now().Unix(), 10)
			baseFilename = fmt.Sprintf("list-all-%s-%s", l.currentDetails.SubscriptionID, timestamp)
		}
	}

	l.Logger().Info("Generated filename from AzureResources", "filename", baseFilename, "count", len(l.resources), "output_dir", outputDir)

	// Create full path with output directory
	jsonFilePath := filepath.Join(outputDir, baseFilename+".json")

	// Send AzureResource objects as JSON
	jsonOutputData := outputters.NewNamedOutputData(l.resources, jsonFilePath)
	l.Send(jsonOutputData)
}
