package azure

import (
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/automation/armautomation"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	jtypes "github.com/praetorian-inc/janus-framework/pkg/types"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// AzureAutomationSecretsLink extracts secrets from Azure Automation Accounts
type AzureAutomationSecretsLink struct {
	*chain.Base
}

func NewAzureAutomationSecretsLink(configs ...cfg.Config) chain.Link {
	l := &AzureAutomationSecretsLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureAutomationSecretsLink) Params() []cfg.Param {
	return []cfg.Param{
		options.AzureSubscription(),
	}
}

func (l *AzureAutomationSecretsLink) Process(resource *model.AzureResource) error {
	subscriptionID := resource.AccountRef

	// Extract resource group and automation account name from resource ID
	resourceGroup, accountName, err := l.parseAutomationResourceID(resource.Key)
	if err != nil {
		return fmt.Errorf("failed to parse automation account resource ID: %w", err)
	}

	// Get Azure credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("failed to get Azure credentials: %w", err)
	}

	// Scan runbooks
	if err := l.scanRunbooks(subscriptionID, resourceGroup, accountName, cred, resource.Key); err != nil {
		l.Logger.Error("Failed to scan runbooks", "error", err.Error())
	}

	// Scan variables
	if err := l.scanVariables(subscriptionID, resourceGroup, accountName, cred, resource.Key); err != nil {
		l.Logger.Error("Failed to scan variables", "error", err.Error())
	}

	return nil
}

func (l *AzureAutomationSecretsLink) scanRunbooks(subscriptionID, resourceGroup, accountName string, cred *azidentity.DefaultAzureCredential, resourceID string) error {
	client, err := armautomation.NewRunbookClient(subscriptionID, cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create runbook client: %w", err)
	}

	l.Logger.Debug("Scanning automation account runbooks",
		"resource_group", resourceGroup,
		"account_name", accountName)

	pager := client.NewListByAutomationAccountPager(resourceGroup, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(l.Context())
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
				npInput := jtypes.NPInput{
					Content: string(metadataContent),
					Provenance: jtypes.NPProvenance{
						Platform:     "azure",
						ResourceType: "Microsoft.Automation/automationAccounts/runbooks",
						ResourceID:   fmt.Sprintf("%s/runbooks/%s", resourceID, *runbook.Name),
						AccountID:    subscriptionID,
					},
				}
				l.Send(npInput)
			}
		}
	}

	return nil
}

func (l *AzureAutomationSecretsLink) scanVariables(subscriptionID, resourceGroup, accountName string, cred *azidentity.DefaultAzureCredential, resourceID string) error {
	client, err := armautomation.NewVariableClient(subscriptionID, cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create variable client: %w", err)
	}

	l.Logger.Debug("Scanning automation account variables",
		"resource_group", resourceGroup,
		"account_name", accountName)

	pager := client.NewListByAutomationAccountPager(resourceGroup, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(l.Context())
		if err != nil {
			return fmt.Errorf("failed to list variables: %w", err)
		}

		for _, variable := range page.Value {
			if variable.Name == nil {
				continue
			}

			// Get variable details
			varDetails, err := client.Get(l.Context(), resourceGroup, accountName, *variable.Name, nil)
			if err != nil {
				l.Logger.Error("Failed to get variable details",
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
				npInput := jtypes.NPInput{
					Content: string(metadataContent),
					Provenance: jtypes.NPProvenance{
						Platform:     "azure",
						ResourceType: "Microsoft.Automation/automationAccounts/variables",
						ResourceID:   fmt.Sprintf("%s/variables/%s", resourceID, *variable.Name),
						AccountID:    subscriptionID,
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
