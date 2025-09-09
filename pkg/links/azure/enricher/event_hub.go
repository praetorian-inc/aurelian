package enricher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventhub/armeventhub"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// EventHubEnricher implements enrichment for Event Hub instances
type EventHubEnricher struct{}

func (e *EventHubEnricher) CanEnrich(templateID string) bool {
	return templateID == "event_hub_public_access"
}

func (e *EventHubEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	// Extract Event Hub name
	eventHubName := resource.Name

	if eventHubName == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing Event Hub name",
			ActualOutput: "Error: Event Hub name is empty",
		})
		return commands
	}

	// Construct Event Hub service endpoint
	serviceEndpoint := fmt.Sprintf("https://%s.servicebus.windows.net", eventHubName)

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Test 1: Event Hub management endpoint discovery
	mgmtURL := fmt.Sprintf("%s/$management", serviceEndpoint)

	resp, err := client.Get(mgmtURL)

	mgmtCommand := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", mgmtURL),
		Description:               "Test anonymous access to Event Hub management endpoint",
		ExpectedOutputDescription: "401 = authentication required | 200 = anonymous access (misconfiguration) | 404 = not found",
	}

	if err != nil {
		mgmtCommand.Error = err.Error()
		mgmtCommand.ActualOutput = fmt.Sprintf("Request failed: %s", err.Error())
	} else {
		defer resp.Body.Close()
		// Read response body
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1000))
		if readErr != nil {
			mgmtCommand.ActualOutput = fmt.Sprintf("Body read error: %s", readErr.Error())
		} else {
			mgmtCommand.ActualOutput = fmt.Sprintf("Body: %s", string(body))
		}
		mgmtCommand.ExitCode = resp.StatusCode
	}

	commands = append(commands, mgmtCommand)

	// Test 2: Retrieve Event Hub namespace network rules
	networkRuleCommand := e.getNetworkRulesCommand(ctx, resource)
	commands = append(commands, networkRuleCommand)

	return commands
}

// getNetworkRulesCommand retrieves network rules for the Event Hub namespace
func (e *EventHubEnricher) getNetworkRulesCommand(ctx context.Context, resource *model.AzureResource) Command {
	namespaceName := resource.Name
	subscriptionID := resource.AccountRef
	resourceGroupName := resource.ResourceGroup

	azCommand := fmt.Sprintf("az eventhubs namespace network-rule-set list --resource-group %s --namespace-name %s", resourceGroupName, namespaceName)

	if namespaceName == "" || subscriptionID == "" || resourceGroupName == "" {
		return Command{
			Command:      azCommand,
			Description:  "Retrieve Event Hub namespace network rules",
			ActualOutput: "Error: Namespace name, subscription ID, or resource group is missing",
			ExitCode:     1,
		}
	}

	// Get network rules from Azure SDK
	networkRules, err := e.retrieveNetworkRules(ctx, subscriptionID, resourceGroupName, namespaceName)
	if err != nil {
		return Command{
			Command:                   azCommand,
			Description:               "Retrieve Event Hub namespace network rules (SDK failed, manual execution required)",
			ExpectedOutputDescription: "List of network rules with IP ranges and virtual network rules | Error = insufficient permissions or namespace not found",
			ActualOutput:              fmt.Sprintf("SDK retrieval failed: %s. Manual execution required", err.Error()),
			Error:                     err.Error(),
			ExitCode:                  1,
		}
	}

	// Format output with network rules
	output := e.formatNetworkRules(networkRules)

	return Command{
		Command:                   azCommand,
		Description:               "Retrieve Event Hub namespace network rules",
		ExpectedOutputDescription: "Network rule configuration with default action and IP/VNet rules",
		ActualOutput:              output,
		ExitCode:                  0,
	}
}

// retrieveNetworkRules gets network rules using Azure SDK
func (e *EventHubEnricher) retrieveNetworkRules(ctx context.Context, subscriptionID, resourceGroupName, namespaceName string) (*armeventhub.NetworkRuleSet, error) {
	// Get Azure credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure credentials: %w", err)
	}

	// Create Event Hub client factory
	clientFactory, err := armeventhub.NewClientFactory(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create client factory: %w", err)
	}

	// Create namespaces client (network rules are accessed through namespaces)
	namespacesClient := clientFactory.NewNamespacesClient()

	// Get network rule set
	response, err := namespacesClient.GetNetworkRuleSet(ctx, resourceGroupName, namespaceName, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get network rules: %w", err)
	}

	return &response.NetworkRuleSet, nil
}

// NetworkRuleSetOutput represents the Azure CLI output format for network rules
type NetworkRuleSetOutput struct {
	ID                          string           `json:"id"`
	Location                    string           `json:"location"`
	Name                        string           `json:"name"`
	ResourceGroup               string           `json:"resourceGroup"`
	Type                        string           `json:"type"`
	DefaultAction               string           `json:"defaultAction"`
	IPRules                     []IPRuleOutput   `json:"ipRules"`
	VirtualNetworkRules         []VNetRuleOutput `json:"virtualNetworkRules"`
	TrustedServiceAccessEnabled bool             `json:"trustedServiceAccessEnabled"`
}

type IPRuleOutput struct {
	IPMask string `json:"ipMask"`
	Action string `json:"action"`
}

type VNetRuleOutput struct {
	Subnet                           SubnetOutput `json:"subnet"`
	IgnoreMissingVNetServiceEndpoint bool         `json:"ignoreMissingVnetServiceEndpoint"`
}

type SubnetOutput struct {
	ID string `json:"id"`
}

// formatNetworkRules formats network rules to match Azure CLI JSON output
func (e *EventHubEnricher) formatNetworkRules(rules *armeventhub.NetworkRuleSet) string {
	if rules == nil {
		return "null"
	}

	output := NetworkRuleSetOutput{
		Type:                        "Microsoft.EventHub/namespaces/networkRuleSets",
		TrustedServiceAccessEnabled: false,
	}

	if rules.ID != nil {
		output.ID = *rules.ID
	}
	if rules.Name != nil {
		output.Name = *rules.Name
	}
	if rules.Location != nil {
		output.Location = *rules.Location
	}

	// Extract resource group from ID if available
	if output.ID != "" {
		parts := strings.Split(output.ID, "/")
		for i, part := range parts {
			if part == "resourceGroups" && i+1 < len(parts) {
				output.ResourceGroup = parts[i+1]
				break
			}
		}
	}

	if rules.Properties != nil {
		if rules.Properties.DefaultAction != nil {
			output.DefaultAction = string(*rules.Properties.DefaultAction)
		}

		if rules.Properties.TrustedServiceAccessEnabled != nil {
			output.TrustedServiceAccessEnabled = *rules.Properties.TrustedServiceAccessEnabled
		}

		// Process IP rules
		if rules.Properties.IPRules != nil {
			for _, ipRule := range rules.Properties.IPRules {
				if ipRule != nil {
					rule := IPRuleOutput{
						Action: "Allow", // Default action for IP rules
					}
					if ipRule.IPMask != nil {
						rule.IPMask = *ipRule.IPMask
					}
					if ipRule.Action != nil {
						rule.Action = string(*ipRule.Action)
					}
					output.IPRules = append(output.IPRules, rule)
				}
			}
		}

		// Process virtual network rules
		if rules.Properties.VirtualNetworkRules != nil {
			for _, vnetRule := range rules.Properties.VirtualNetworkRules {
				if vnetRule != nil {
					rule := VNetRuleOutput{
						IgnoreMissingVNetServiceEndpoint: false,
					}
					if vnetRule.Subnet != nil && vnetRule.Subnet.ID != nil {
						rule.Subnet.ID = *vnetRule.Subnet.ID
					}
					if vnetRule.IgnoreMissingVnetServiceEndpoint != nil {
						rule.IgnoreMissingVNetServiceEndpoint = *vnetRule.IgnoreMissingVnetServiceEndpoint
					}
					output.VirtualNetworkRules = append(output.VirtualNetworkRules, rule)
				}
			}
		}
	}

	jsonOutput, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error formatting output: %s", err.Error())
	}

	return string(jsonOutput)
}
