package recon

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.Register(&ARGScan{})
}

// ARGScan scans Azure resources using ARG templates and enriches findings
type ARGScan struct{}

func (m *ARGScan) ID() string {
	return "arg-scan"
}

func (m *ARGScan) Name() string {
	return "Azure ARG Template Scanner with Enrichment"
}

func (m *ARGScan) Description() string {
	return "Scans Azure resources using ARG templates and enriches findings with security testing commands (only runs templates with arg-scan category)."
}

func (m *ARGScan) Platform() plugin.Platform {
	return plugin.PlatformAzure
}

func (m *ARGScan) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *ARGScan) OpsecLevel() string {
	return "moderate"
}

func (m *ARGScan) Authors() []string {
	return []string{"Praetorian"}
}

func (m *ARGScan) References() []string {
	return []string{}
}

func (m *ARGScan) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "subscription",
			Description: "Azure subscription ID (or 'all' to resolve to all subscriptions)",
			Type:        "string",
			Required:    true,
		},
		{
			Name:        "disable-enrichment",
			Description: "Disable enrichment of findings with security testing commands",
			Type:        "bool",
			Required:    false,
			Default:     false,
		},
		{
			Name:        "module-name",
			Description: "Name of the module for dynamic file naming",
			Type:        "string",
			Required:    false,
			Default:     "arg-scan",
		},
		{
			Name:        "category",
			Description: "Template category filter",
			Type:        "string",
			Required:    false,
			Default:     "arg-scan",
		},
	}
}

func (m *ARGScan) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Get context
	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	// Get parameters from config
	subscriptionParam, _ := cfg.Args["subscription"].(string)
	if subscriptionParam == "" {
		return nil, fmt.Errorf("subscription parameter is required")
	}

	disableEnrichment, _ := cfg.Args["disable-enrichment"].(bool)
	moduleName, _ := cfg.Args["module-name"].(string)
	if moduleName == "" {
		moduleName = "arg-scan"
	}

	category, _ := cfg.Args["category"].(string)
	if category == "" {
		category = "arg-scan"
	}

	// Check context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Resolve subscriptions
	var subscriptions []string
	if strings.EqualFold(subscriptionParam, "all") {
		subs, err := helpers.ListSubscriptions(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to list subscriptions: %w", err)
		}
		subscriptions = subs

		if cfg.Verbose {
			fmt.Fprintf(cfg.Output, "Resolved 'all' to %d subscriptions\n", len(subscriptions))
		}
	} else {
		subscriptions = []string{subscriptionParam}
	}

	// Load templates with category filter
	loader, err := templates.NewTemplateLoader(templates.LoadEmbedded)
	if err != nil {
		return nil, fmt.Errorf("failed to load templates: %w", err)
	}

	templatesList := loader.GetTemplates()
	var filteredTemplates []*templates.ARGQueryTemplate
	for _, t := range templatesList {
		if slices.Contains(t.Category, category) {
			filteredTemplates = append(filteredTemplates, t)
		}
	}

	if len(filteredTemplates) == 0 {
		return nil, fmt.Errorf("no templates found for category: %s", category)
	}

	if cfg.Verbose {
		fmt.Fprintf(cfg.Output, "Scanning Azure subscriptions: %v\n", subscriptions)
		fmt.Fprintf(cfg.Output, "Module name: %s, Category: %s\n", moduleName, category)
		fmt.Fprintf(cfg.Output, "Loaded %d templates for category '%s'\n", len(filteredTemplates), category)
		fmt.Fprintf(cfg.Output, "Enrichment: %v\n", !disableEnrichment)
	}

	// Create ARG client
	argClient, err := helpers.NewARGClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create ARG client: %w", err)
	}

	var allResults []plugin.Result

	// Execute queries for each subscription x template
	for _, subscription := range subscriptions {
		for _, template := range filteredTemplates {
			// Check context cancellation
			select {
			case <-ctx.Done():
				return allResults, ctx.Err()
			default:
			}

			if cfg.Verbose {
				fmt.Fprintf(cfg.Output, "Executing template '%s' on subscription %s\n", template.Name, subscription)
			}

			opts := &helpers.ARGQueryOptions{
				Subscriptions: []string{subscription},
			}

			err := argClient.ExecutePaginatedQuery(ctx, template.Query, opts, func(response *armresourcegraph.ClientResourcesResponse) error {
				if response == nil || response.Data == nil {
					return nil
				}

				rows, ok := response.Data.([]interface{})
				if !ok {
					return nil
				}

				for _, row := range rows {
					item, ok := row.(map[string]interface{})
					if !ok {
						continue
					}

					resultData := map[string]any{
						"id":            helpers.SafeGetString(item, "id"),
						"name":          helpers.SafeGetString(item, "name"),
						"type":          helpers.SafeGetString(item, "type"),
						"location":      helpers.SafeGetString(item, "location"),
						"subscription":  subscription,
						"template_id":   template.ID,
						"template_name": template.Name,
						"severity":      template.Severity,
						"properties":    item,
					}

					// Add enrichment if enabled
					if !disableEnrichment {
						resultData["enrichment"] = generateEnrichment(template, item)
					}

					result := plugin.Result{
						Data: resultData,
						Metadata: map[string]any{
							"module":   moduleName,
							"category": category,
							"platform": "azure",
						},
					}

					allResults = append(allResults, result)
				}
				return nil
			})

			if err != nil {
				slog.Warn("Failed to execute template query",
					"template", template.ID,
					"subscription", subscription,
					"error", err)
				if cfg.Verbose {
					fmt.Fprintf(cfg.Output, "Warning: query failed for template %s: %v\n", template.ID, err)
				}
				continue
			}
		}
	}

	if cfg.Verbose {
		fmt.Fprintf(cfg.Output, "Scan complete. Total results: %d\n", len(allResults))
	}

	return allResults, nil
}

// generateEnrichment creates security testing commands for a finding
func generateEnrichment(template *templates.ARGQueryTemplate, resource map[string]any) map[string]any {
	enrichment := map[string]any{
		"triage_notes": template.TriageNotes,
		"references":   template.References,
	}

	// Add resource-type specific commands
	resourceType := helpers.SafeGetString(resource, "type")
	resourceName := helpers.SafeGetString(resource, "name")

	switch {
	case strings.Contains(strings.ToLower(resourceType), "storage"):
		enrichment["test_commands"] = []string{
			fmt.Sprintf("az storage account show --name %s", resourceName),
			fmt.Sprintf("az storage container list --account-name %s", resourceName),
		}
	case strings.Contains(strings.ToLower(resourceType), "keyvault"):
		enrichment["test_commands"] = []string{
			fmt.Sprintf("az keyvault secret list --vault-name %s", resourceName),
		}
	case strings.Contains(strings.ToLower(resourceType), "web"):
		enrichment["test_commands"] = []string{
			fmt.Sprintf("az webapp show --name %s", resourceName),
			fmt.Sprintf("az webapp config appsettings list --name %s", resourceName),
		}
	}

	return enrichment
}
