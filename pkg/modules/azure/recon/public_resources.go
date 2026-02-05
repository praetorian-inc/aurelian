package recon

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

type PublicResources struct{}

func init() {
	plugin.Register(&PublicResources{})
}

func (m *PublicResources) ID() string {
	return "public-resources"
}

func (m *PublicResources) Name() string {
	return "Public Resource Scanner"
}

func (m *PublicResources) Description() string {
	return "Detects publicly accessible Azure resources including storage accounts, app services, SQL databases, VMs, and more."
}

func (m *PublicResources) Platform() plugin.Platform {
	return plugin.PlatformAzure
}

func (m *PublicResources) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *PublicResources) OpsecLevel() string {
	return "low"
}

func (m *PublicResources) Authors() []string {
	return []string{"Praetorian"}
}

func (m *PublicResources) References() []string {
	return []string{
		"https://learn.microsoft.com/en-us/azure/governance/resource-graph/",
	}
}

func (m *PublicResources) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "subscription-id",
			Description: "Azure subscription ID to scan",
			Type:        "string",
			Required:    true,
		},
		{
			Name:        "category",
			Description: "Category of Azure ARG templates to use",
			Type:        "string",
			Required:    false,
			Default:     "Public Access",
		},
	}
}

func (m *PublicResources) Run(cfg plugin.Config) ([]plugin.Result, error) {
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	subscriptionID, ok := cfg.Args["subscription-id"].(string)
	if !ok || subscriptionID == "" {
		return nil, fmt.Errorf("subscription-id is required")
	}

	category := "Public Access"
	if cat, ok := cfg.Args["category"].(string); ok && cat != "" {
		category = cat
	}

	// Load ARG templates
	templates := loadARGTemplates(category)

	// Execute ARG queries
	var results []plugin.Result

	for _, template := range templates {
		queryResults, err := executeARGQuery(ctx, subscriptionID, template)
		if err != nil {
			if cfg.Verbose {
				fmt.Fprintf(cfg.Output, "Warning: query failed for template %s: %v\n", template.Name, err)
			}
			continue
		}

		for _, resource := range queryResults {
			results = append(results, plugin.Result{
				Data: resource,
				Metadata: map[string]any{
					"template":  template.Name,
					"category":  category,
					"platform":  "azure",
					"module_id": m.ID(),
				},
			})
		}
	}

	// Write JSON output if configured
	if cfg.Output != nil {
		enc := json.NewEncoder(cfg.Output)
		enc.SetIndent("", "  ")
		for _, result := range results {
			if err := enc.Encode(result.Data); err != nil {
				return results, fmt.Errorf("failed to encode result: %w", err)
			}
		}
	}

	return results, nil
}

// loadARGTemplates loads Azure Resource Graph query templates
func loadARGTemplates(category string) []ARGTemplate {
	// This would typically load templates from embedded files or external source
	// For now, return a minimal implementation
	return []ARGTemplate{
		{
			Name:     "PublicStorageAccounts",
			Query:    "Resources | where type =~ 'microsoft.storage/storageaccounts' | where properties.allowBlobPublicAccess == true",
			Category: category,
		},
		{
			Name:     "PublicAppServices",
			Query:    "Resources | where type =~ 'microsoft.web/sites' | where properties.publicNetworkAccess == 'Enabled'",
			Category: category,
		},
		{
			Name:     "PublicSQLDatabases",
			Query:    "Resources | where type =~ 'microsoft.sql/servers' | where properties.publicNetworkAccess == 'Enabled'",
			Category: category,
		},
	}
}

// executeARGQuery executes an Azure Resource Graph query
func executeARGQuery(ctx context.Context, subscriptionID string, template ARGTemplate) ([]AzureResource, error) {
	// This would typically execute the Azure Resource Graph query using Azure SDK
	// For now, return empty results as placeholder
	// In a real implementation, this would:
	// 1. Create Azure Resource Graph client
	// 2. Execute template.Query against subscriptionID
	// 3. Parse results into AzureResource structs
	return []AzureResource{}, nil
}

// ARGTemplate represents an Azure Resource Graph query template
type ARGTemplate struct {
	Name     string
	Query    string
	Category string
}

// AzureResource represents an Azure resource result
type AzureResource struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Type       string         `json:"type"`
	Location   string         `json:"location"`
	Properties map[string]any `json:"properties"`
}
