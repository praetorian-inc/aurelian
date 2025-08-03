package azure

import (
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// AzureResourceAggregatorLink collects Azure resources and outputs them with filename generation
type AzureResourceAggregatorLink struct {
	*chain.Base
	resources          []model.AzureResource
	resourceDetails    []*types.AzureResourceDetails
	currentDetails     *types.AzureResourceDetails
}

func NewAzureResourceAggregatorLink(configs ...cfg.Config) chain.Link {
	l := &AzureResourceAggregatorLink{
		resources:       make([]model.AzureResource, 0),
		resourceDetails: make([]*types.AzureResourceDetails, 0),
	}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureResourceAggregatorLink) Params() []cfg.Param {
	return []cfg.Param{
		options.OutputDir(),
		cfg.NewParam[string]("filename", "Base filename for output").
			WithDefault("").
			WithShortcode("f"),
	}
}

func (l *AzureResourceAggregatorLink) Process(input any) error {
	switch v := input.(type) {
	case model.AzureResource:
		l.resources = append(l.resources, v)
		l.Logger.Debug("Aggregated AzureResource", "type", v.ResourceType, "id", v.Key, "total", len(l.resources))
		
	case *types.AzureResourceDetails:
		l.resourceDetails = append(l.resourceDetails, v)
		l.currentDetails = v // Keep track of the latest details for metadata
		l.Logger.Debug("Aggregated AzureResourceDetails", "subscription", v.SubscriptionID, "count", len(v.Resources))
		
	default:
		l.Logger.Debug("Received unknown input type", "type", fmt.Sprintf("%T", input))
	}
	
	return nil
}

func (l *AzureResourceAggregatorLink) Complete() error {
	filename, _ := cfg.As[string](l.Arg("filename"))
	
	l.Logger.Info("Aggregation complete", "azure_resources", len(l.resources), "resource_details", len(l.resourceDetails))
	
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
	outputDir, _ := cfg.As[string](l.Arg("output"))
	
	// Generate filename if not provided
	if baseFilename == "" {
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		baseFilename = fmt.Sprintf("list-all-%s-%s", resourceDetails.SubscriptionID, timestamp)
	} else {
		baseFilename = baseFilename + "-" + resourceDetails.SubscriptionID
	}
	
	l.Logger.Info("Generated filename", "filename", baseFilename, "subscription", resourceDetails.SubscriptionID, "output_dir", outputDir)
	
	// Convert to EnrichedResourceDescription for JSON output
	var enrichedResources []types.EnrichedResourceDescription
	for _, resource := range resourceDetails.Resources {
		props := make(map[string]interface{})
		for k, v := range resource.Properties {
			props[k] = v
		}
		props["name"] = resource.Name
		props["tags"] = resource.Tags
		
		enrichedResource := types.EnrichedResourceDescription{
			Identifier: resource.ID,
			TypeName:   resource.Type,
			Region:     resource.Location,
			AccountId:  resourceDetails.SubscriptionID,
			Properties: props,
		}
		
		enrichedResources = append(enrichedResources, enrichedResource)
	}
	
	// Create full paths with output directory
	jsonFilePath := filepath.Join(outputDir, baseFilename+".json")
	mdFilePath := filepath.Join(outputDir, baseFilename+".md")
	
	// Send JSON output
	jsonOutputData := outputters.NewNamedOutputData(enrichedResources, jsonFilePath)
	l.Send(jsonOutputData)
	
	// Send Markdown output
	markdownTable := l.createResourceListTable(resourceDetails)
	markdownOutputData := outputters.NewNamedOutputData(markdownTable, mdFilePath)
	l.Send(markdownOutputData)
}

func (l *AzureResourceAggregatorLink) generateOutputFromAzureResources(baseFilename string) {
	// Get output directory
	outputDir, _ := cfg.As[string](l.Arg("output"))
	
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
	
	l.Logger.Info("Generated filename from AzureResources", "filename", baseFilename, "count", len(l.resources), "output_dir", outputDir)
	
	// Create full path with output directory
	jsonFilePath := filepath.Join(outputDir, baseFilename+".json")
	
	// Send AzureResource objects as JSON
	jsonOutputData := outputters.NewNamedOutputData(l.resources, jsonFilePath)
	l.Send(jsonOutputData)
}

// Helper function to create resource list table
func (l *AzureResourceAggregatorLink) createResourceListTable(details *types.AzureResourceDetails) types.MarkdownTable {
	var markdownContent []string
	markdownContent = append(markdownContent, fmt.Sprintf("# Azure Resources List"))
	markdownContent = append(markdownContent, fmt.Sprintf("Subscription: %s (%s)", details.SubscriptionName, details.SubscriptionID))
	markdownContent = append(markdownContent, fmt.Sprintf("Tenant: %s (%s)", details.TenantName, details.TenantID))
	markdownContent = append(markdownContent, "")
	
	table := types.MarkdownTable{
		TableHeading: fmt.Sprintf("Azure Resources List\\nSubscription: %s (%s)\\nTenant: %s (%s)",
			details.SubscriptionName, details.SubscriptionID, details.TenantName, details.TenantID),
		Headers: []string{"Resource Name", "Type", "Location", "Resource Group"},
		Rows:    make([][]string, 0),
	}
	
	for _, resource := range details.Resources {
		table.Rows = append(table.Rows, []string{
			resource.Name,
			resource.Type,
			resource.Location,
			resource.ResourceGroup,
		})
	}
	
	return table
}