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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/servicebus/armservicebus"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// ServiceBusEnricher implements enrichment for Service Bus instances
type ServiceBusEnricher struct{}

func (s *ServiceBusEnricher) CanEnrich(templateID string) bool {
	return templateID == "service_bus_public_access"
}

func (s *ServiceBusEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	serviceBusName := resource.Name
	if serviceBusName == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing Service Bus name",
			ActualOutput: "Error: Service Bus name is empty",
		})
		return commands
	}

	var serviceEndpoint string
	if endpoint, exists := resource.Properties["serviceBusEndpoint"].(string); exists && endpoint != "" {
		serviceEndpoint = endpoint
		if strings.HasSuffix(serviceEndpoint, "/") {
			serviceEndpoint = strings.TrimSuffix(serviceEndpoint, "/")
		}
		if strings.HasSuffix(serviceEndpoint, ":443") {
			serviceEndpoint = strings.TrimSuffix(serviceEndpoint, ":443")
		}
	} else {
		serviceEndpoint = fmt.Sprintf("https://%s.servicebus.windows.net", serviceBusName)
	}
	client := &http.Client{Timeout: 10 * time.Second}

	// Test 1: Service Bus management endpoint
	mgmtURL := fmt.Sprintf("%s/$management", serviceEndpoint)
	req, err := http.NewRequestWithContext(ctx, "GET", mgmtURL, nil)
	if err != nil {
		mgmtCommand := Command{
			Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", mgmtURL),
			Description:               "Test anonymous access to Service Bus management endpoint",
			ExpectedOutputDescription: "401 = authentication required | 200 = anonymous access | 404 = not found",
			Error:                     err.Error(),
			ActualOutput:              fmt.Sprintf("Request creation failed: %s", err.Error()),
		}
		commands = append(commands, mgmtCommand)
		return commands
	}
	resp, err := client.Do(req)

	mgmtCommand := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", mgmtURL),
		Description:               "Test anonymous access to Service Bus management endpoint",
		ExpectedOutputDescription: "401 = authentication required | 200 = anonymous access | 404 = not found",
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

	// Test 2: Retrieve Service Bus namespace network rules
	networkRuleCommand := s.getNetworkRulesCommand(ctx, resource)
	commands = append(commands, networkRuleCommand)

	// Test 3: Azure CLI Service Bus test
	commands = append(commands, Command{
		Command:                   fmt.Sprintf("az servicebus namespace show --name %s --resource-group %s", serviceBusName, resource.ResourceGroup),
		Description:               "Azure CLI command to show Service Bus namespace details",
		ExpectedOutputDescription: "Namespace details = accessible via Azure API | Error = access denied",
		ActualOutput:              "Manual execution required - requires Azure CLI authentication",
	})

	return commands
}

// getNetworkRulesCommand retrieves network rules for the Service Bus namespace
func (s *ServiceBusEnricher) getNetworkRulesCommand(ctx context.Context, resource *model.AzureResource) Command {
	namespaceName := resource.Name
	subscriptionID := resource.AccountRef
	resourceGroupName := resource.ResourceGroup

	azCommand := fmt.Sprintf("az servicebus namespace network-rule-set show --resource-group %s --namespace-name %s", resourceGroupName, namespaceName)

	if namespaceName == "" || subscriptionID == "" || resourceGroupName == "" {
		return Command{
			Command:      azCommand,
			Description:  "Retrieve Service Bus namespace network rules",
			ActualOutput: "Error: Namespace name, subscription ID, or resource group is missing",
			ExitCode:     1,
		}
	}

	// Get network rules from Azure SDK
	networkRules, err := s.retrieveNetworkRules(ctx, subscriptionID, resourceGroupName, namespaceName)
	if err != nil {
		return Command{
			Command:                   azCommand,
			Description:               "Retrieve Service Bus namespace network rules (SDK failed, manual execution required)",
			ExpectedOutputDescription: "List of network rules with IP ranges and virtual network rules | Error = insufficient permissions or namespace not found",
			ActualOutput:              fmt.Sprintf("SDK retrieval failed: %s. Manual execution required", err.Error()),
			Error:                     err.Error(),
			ExitCode:                  1,
		}
	}

	// Format output with network rules
	output := s.formatNetworkRules(networkRules)

	return Command{
		Command:                   azCommand,
		Description:               "Retrieve Service Bus namespace network rules",
		ExpectedOutputDescription: "Network rule configuration with default action and IP/VNet rules",
		ActualOutput:              output,
		ExitCode:                  0,
	}
}

// retrieveNetworkRules gets network rules using Azure SDK
func (s *ServiceBusEnricher) retrieveNetworkRules(ctx context.Context, subscriptionID, resourceGroupName, namespaceName string) (*armservicebus.NetworkRuleSet, error) {
	// Get Azure credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure credentials: %w", err)
	}

	// Create Service Bus client factory
	clientFactory, err := armservicebus.NewClientFactory(subscriptionID, cred, nil)
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

// ServiceBusNetworkRuleSetOutput represents the Azure CLI output format for Service Bus network rules
type ServiceBusNetworkRuleSetOutput struct {
	ID                          string                     `json:"id"`
	Location                    string                     `json:"location"`
	Name                        string                     `json:"name"`
	ResourceGroup               string                     `json:"resourceGroup"`
	Type                        string                     `json:"type"`
	DefaultAction               string                     `json:"defaultAction"`
	IPRules                     []ServiceBusIPRuleOutput   `json:"ipRules"`
	VirtualNetworkRules         []ServiceBusVNetRuleOutput `json:"virtualNetworkRules"`
	TrustedServiceAccessEnabled bool                       `json:"trustedServiceAccessEnabled"`
	PublicNetworkAccess         string                     `json:"publicNetworkAccess"`
}

type ServiceBusIPRuleOutput struct {
	IPMask string `json:"ipMask"`
	Action string `json:"action"`
}

type ServiceBusVNetRuleOutput struct {
	Subnet                           ServiceBusSubnetOutput `json:"subnet"`
	IgnoreMissingVNetServiceEndpoint bool                   `json:"ignoreMissingVnetServiceEndpoint"`
}

type ServiceBusSubnetOutput struct {
	ID string `json:"id"`
}

// formatNetworkRules formats network rules to match Azure CLI JSON output
func (s *ServiceBusEnricher) formatNetworkRules(rules *armservicebus.NetworkRuleSet) string {
	if rules == nil {
		return "null"
	}

	output := ServiceBusNetworkRuleSetOutput{
		Type:                        "Microsoft.ServiceBus/namespaces/networkRuleSets",
		TrustedServiceAccessEnabled: false,
		PublicNetworkAccess:         "Enabled",
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

		if rules.Properties.PublicNetworkAccess != nil {
			output.PublicNetworkAccess = string(*rules.Properties.PublicNetworkAccess)
		}

		// Process IP rules
		if rules.Properties.IPRules != nil {
			for _, ipRule := range rules.Properties.IPRules {
				if ipRule != nil {
					rule := ServiceBusIPRuleOutput{
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
					rule := ServiceBusVNetRuleOutput{
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
