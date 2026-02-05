package azure

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/automation/armautomation"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/links/azure/base"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// AzureAutomationSecretsLink extracts secrets from Azure Automation Accounts
type AzureAutomationSecretsLink struct {
	*base.NativeAzureLink
}

func NewAzureAutomationSecretsLink(args map[string]any) *AzureAutomationSecretsLink {
	return &AzureAutomationSecretsLink{
		NativeAzureLink: base.NewNativeAzureLink("azure-automation-secrets", args),
	}
}

func (l *AzureAutomationSecretsLink) Parameters() []plugin.Parameter {
	return base.StandardAzureParams()
}

func (l *AzureAutomationSecretsLink) Process(ctx context.Context, input any) ([]any, error) {
	resource, ok := input.(*output.CloudResource)
	if !ok {
		return nil, fmt.Errorf("expected *output.CloudResource, got %T", input)
	}

	subscriptionID := resource.AccountRef

	// Extract resource group and automation account name from resource ID
	resourceGroup, accountName, err := l.parseAutomationResourceID(resource.ResourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse automation account resource ID: %w", err)
	}

	// Get Azure credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure credentials: %w", err)
	}

	// Scan runbooks
	if err := l.scanRunbooks(ctx, subscriptionID, resourceGroup, accountName, cred, resource.ResourceID); err != nil {
		l.Logger().Error("Failed to scan runbooks", "error", err.Error())
	}

	// Scan variables
	if err := l.scanVariables(ctx, subscriptionID, resourceGroup, accountName, cred, resource.ResourceID); err != nil {
		l.Logger().Error("Failed to scan variables", "error", err.Error())
	}

	return l.Outputs(), nil
}

func (l *AzureAutomationSecretsLink) scanRunbooks(ctx context.Context, subscriptionID, resourceGroup, accountName string, cred *azidentity.DefaultAzureCredential, resourceID string) error {
	client, err := armautomation.NewRunbookClient(subscriptionID, cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create runbook client: %w", err)
	}

	l.Logger().Debug("Scanning automation account runbooks",
		"resource_group", resourceGroup,
		"account_name", accountName)

	pager := client.NewListByAutomationAccountPager(resourceGroup, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("failed to list runbooks: %w", err)
		}

		for _, runbook := range page.Value {
			if runbook.Name == nil {
				continue
			}

			// Create metadata for NoseyParker scanning (without content extraction for now)
			runbookMetadata := map[string]interface{}{
				"name":       *runbook.Name,
				"id":         runbook.ID,
				"type":       runbook.Type,
				"properties": runbook.Properties,
			}

			// Convert metadata to JSON for scanning
			metadataContent, err := json.Marshal(runbookMetadata)
			if err == nil {
				npInput := map[string]any{
					"content": string(metadataContent),
					"provenance": map[string]any{
						"platform":      "azure",
						"resource_type": "Microsoft.Automation/automationAccounts/runbooks",
						"resource_id":   fmt.Sprintf("%s/runbooks/%s", resourceID, *runbook.Name),
						"account_id":    subscriptionID,
					},
				}
				l.Send(npInput)
			}
		}
	}

	return nil
}

func (l *AzureAutomationSecretsLink) scanVariables(ctx context.Context, subscriptionID, resourceGroup, accountName string, cred *azidentity.DefaultAzureCredential, resourceID string) error {
	client, err := armautomation.NewVariableClient(subscriptionID, cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create variable client: %w", err)
	}

	l.Logger().Debug("Scanning automation account variables",
		"resource_group", resourceGroup,
		"account_name", accountName)

	pager := client.NewListByAutomationAccountPager(resourceGroup, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("failed to list variables: %w", err)
		}

		for _, variable := range page.Value {
			if variable.Name == nil {
				continue
			}

			// Get variable details
			varDetails, err := client.Get(ctx, resourceGroup, accountName, *variable.Name, nil)
			if err != nil {
				l.Logger().Error("Failed to get variable details",
					"variable", *variable.Name,
					"error", err.Error())
				continue
			}

			// Create metadata for scanning (variables may contain secret information)
			variableMetadata := map[string]interface{}{
				"name":       *variable.Name,
				"id":         variable.ID,
				"properties": varDetails.Properties,
				"value":      varDetails.Properties, // Properties contain variable details
			}

			// Convert to JSON for scanning
			metadataContent, err := json.Marshal(variableMetadata)
			if err == nil {
				npInput := map[string]any{
					"content": string(metadataContent),
					"provenance": map[string]any{
						"platform":      "azure",
						"resource_type": "Microsoft.Automation/automationAccounts/variables",
						"resource_id":   fmt.Sprintf("%s/variables/%s", resourceID, *variable.Name),
						"account_id":    subscriptionID,
					},
				}
				l.Send(npInput)
			}
		}
	}

	return nil
}

func (l *AzureAutomationSecretsLink) parseAutomationResourceID(resourceID string) (resourceGroup, accountName string, err error) {
	parsed, err := helpers.ParseAzureResourceID(resourceID)
	if err != nil {
		return "", "", err
	}

	resourceGroup = parsed["resourceGroups"]
	accountName = parsed["automationAccounts"]

	if resourceGroup == "" || accountName == "" {
		return "", "", fmt.Errorf("invalid automation account resource ID format")
	}

	return resourceGroup, accountName, nil
}
