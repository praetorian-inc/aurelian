package recon

import (
	"context"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AzureFindSecretsModule{})
}

// AzureFindSecretsModule enumerates Azure resources and finds secrets using NoseyParker
// across VMs, web apps, automation accounts, key vaults, and storage accounts
type AzureFindSecretsModule struct{}

// Metadata methods

func (m *AzureFindSecretsModule) ID() string {
	return "find-secrets"
}

func (m *AzureFindSecretsModule) Name() string {
	return "Azure Find Secrets"
}

func (m *AzureFindSecretsModule) Description() string {
	return "Enumerate Azure resources and find secrets using NoseyParker across VMs, web apps, automation accounts, key vaults, and storage accounts"
}

func (m *AzureFindSecretsModule) Platform() plugin.Platform {
	return plugin.PlatformAzure
}

func (m *AzureFindSecretsModule) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *AzureFindSecretsModule) OpsecLevel() string {
	return "moderate"
}

func (m *AzureFindSecretsModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *AzureFindSecretsModule) References() []string {
	return []string{
		"https://learn.microsoft.com/en-us/azure/azure-resource-graph/overview",
		"https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts",
	}
}

// Parameters defines the module parameters
func (m *AzureFindSecretsModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "subscription-id",
			Description: "Azure subscription ID to scan (optional, defaults to all accessible subscriptions)",
			Type:        "string",
			Required:    false,
			Shortcode:   "s",
		},
		{
			Name:        "resource-types",
			Description: "Comma-separated list of Azure resource types to scan for secrets (e.g., 'VirtualMachine,WebApp,AutomationAccount,KeyVault,StorageAccount')",
			Type:        "string",
			Required:    false,
			Default:     "VirtualMachine,WebApp,AutomationAccount,KeyVault,StorageAccount",
			Shortcode:   "t",
		},
		{
			Name:        "category",
			Description: "Category of Azure Resource Graph templates to use",
			Type:        "string",
			Required:    false,
			Default:     "secrets",
			Shortcode:   "c",
		},
		{
			Name:        "module-name",
			Description: "Name of the module for dynamic file naming",
			Type:        "string",
			Required:    false,
			Default:     "find-secrets",
			Shortcode:   "m",
		},
		{
			Name:        "continue-piping",
			Description: "Continue piping output to subsequent processors",
			Type:        "bool",
			Required:    false,
			Default:     true,
		},
	}
}

// Run executes the Azure Find Secrets module
func (m *AzureFindSecretsModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	// Extract parameters
	subscriptionID, _ := cfg.Args["subscription-id"].(string)
	resourceTypes, _ := cfg.Args["resource-types"].(string)
	if resourceTypes == "" {
		resourceTypes = "VirtualMachine,WebApp,AutomationAccount,KeyVault,StorageAccount"
	}

	category, _ := cfg.Args["category"].(string)
	if category == "" {
		category = "secrets"
	}

	moduleName, _ := cfg.Args["module-name"].(string)
	if moduleName == "" {
		moduleName = "find-secrets"
	}

	continuePiping, _ := cfg.Args["continue-piping"].(bool)

	// TODO: Implement the full secret scanning workflow
	// This consolidates the following Janus chain links:
	// 1. Azure subscription generation (azure.NewAzureSubscriptionGeneratorLink)
	// 2. ARG template loading (azure.NewARGTemplateLoaderLink)
	// 3. ARG template query execution (azure.NewARGTemplateQueryLink)
	// 4. Azure secret finding (azure.NewAzureFindSecretsLink)
	// 5. NoseyParker scanning (noseyparker.NewNoseyParkerScanner)
	//
	// Implementation steps:
	// 1. Generate Azure subscription context(s)
	// 2. Load Azure Resource Graph query templates for the specified category
	// 3. Execute ARG queries to enumerate resources by type
	// 4. For each resource, extract content (environment variables, configs, etc.)
	// 5. Run NoseyParker scanner on extracted content
	// 6. Aggregate and format findings
	// 7. Apply appropriate output formatting (JSON + console for NP findings)

	// Placeholder result until full implementation
	return []plugin.Result{
		{
			Data: map[string]any{
				"subscription_id":   subscriptionID,
				"resource_types":    resourceTypes,
				"category":          category,
				"module_name":       moduleName,
				"continue_piping":   continuePiping,
				"scan_status":       "pending_implementation",
				"message":           "Full secret scanning workflow to be implemented",
				"implementation_notes": []string{
					"Step 1: Generate Azure subscription context(s)",
					"Step 2: Load ARG query templates for category: " + category,
					"Step 3: Execute ARG queries to enumerate resources",
					"Step 4: Extract content from enumerated resources",
					"Step 5: Run NoseyParker scanner on content",
					"Step 6: Aggregate and format findings",
					"Step 7: Apply JSON + NoseyParker console output formatting",
				},
			},
			Metadata: map[string]any{
				"platform":    string(m.Platform()),
				"category":    string(m.Category()),
				"opsec_level": m.OpsecLevel(),
				"authors":     m.Authors(),
				"references":  m.References(),
			},
		},
	}, nil
}
