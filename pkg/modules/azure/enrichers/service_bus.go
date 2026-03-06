package enrichers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/servicebus/armservicebus"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("service_bus_public_access", enrichServiceBus)
}

func enrichServiceBus(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	serviceBusName := result.ResourceName
	if serviceBusName == "" {
		return nil, nil
	}

	var serviceEndpoint string
	if endpoint, ok := result.Properties["serviceBusEndpoint"].(string); ok && endpoint != "" {
		serviceEndpoint = endpoint
		serviceEndpoint = strings.TrimSuffix(serviceEndpoint, "/")
		serviceEndpoint = strings.TrimSuffix(serviceEndpoint, ":443")
	} else {
		serviceEndpoint = fmt.Sprintf("https://%s.servicebus.windows.net", serviceBusName)
	}

	client := NewHTTPClient(10 * time.Second)
	var commands []plugin.AzureEnrichmentCommand

	// Test 1: Service Bus management endpoint
	mgmtURL := fmt.Sprintf("%s/$management", serviceEndpoint)
	curlEquiv := fmt.Sprintf("curl -i '%s' --max-time 10", mgmtURL)
	commands = append(commands, HTTPProbe(client, mgmtURL, curlEquiv,
		"Test anonymous access to Service Bus management endpoint",
		"401 = authentication required | 200 = anonymous access | 404 = not found",
	))

	// Test 2: Retrieve Service Bus namespace network rules via SDK
	subscriptionID := result.SubscriptionID
	resourceGroup := ParseResourceGroup(result.ResourceID)
	networkCmd := getServiceBusNetworkRulesCommand(cfg, subscriptionID, resourceGroup, serviceBusName)
	commands = append(commands, networkCmd)

	return commands, nil
}

func getServiceBusNetworkRulesCommand(cfg plugin.AzureEnricherConfig, subscriptionID, resourceGroup, namespaceName string) plugin.AzureEnrichmentCommand {
	azCommand := fmt.Sprintf("az servicebus namespace network-rule-set show --resource-group %s --namespace-name %s", resourceGroup, namespaceName)

	if namespaceName == "" || subscriptionID == "" || resourceGroup == "" {
		return plugin.AzureEnrichmentCommand{
			Command:      azCommand,
			Description:  "Retrieve Service Bus namespace network rules",
			ActualOutput: "Error: Namespace name, subscription ID, or resource group is missing",
			ExitCode:     1,
		}
	}

	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	clientFactory, err := armservicebus.NewClientFactory(subscriptionID, cfg.Credential, nil)
	if err != nil {
		return plugin.AzureEnrichmentCommand{
			Command:      azCommand,
			Description:  "Retrieve Service Bus namespace network rules (SDK failed)",
			ActualOutput: fmt.Sprintf("SDK retrieval failed: %s", err.Error()),
			Error:        err.Error(),
			ExitCode:     1,
		}
	}

	namespacesClient := clientFactory.NewNamespacesClient()
	response, err := namespacesClient.GetNetworkRuleSet(ctx, resourceGroup, namespaceName, nil)
	if err != nil {
		return plugin.AzureEnrichmentCommand{
			Command:      azCommand,
			Description:  "Retrieve Service Bus namespace network rules (SDK failed)",
			ActualOutput: fmt.Sprintf("SDK retrieval failed: %s", err.Error()),
			Error:        err.Error(),
			ExitCode:     1,
		}
	}

	output := formatServiceBusNetworkRules(&response.NetworkRuleSet)

	return plugin.AzureEnrichmentCommand{
		Command:                   azCommand,
		Description:               "Retrieve Service Bus namespace network rules",
		ExpectedOutputDescription: "Network rule configuration with default action and IP/VNet rules",
		ActualOutput:              output,
		ExitCode:                  0,
	}
}

func formatServiceBusNetworkRules(rules *armservicebus.NetworkRuleSet) string {
	if rules == nil {
		return "null"
	}

	type ipRuleOutput struct {
		IPMask string `json:"ipMask"`
		Action string `json:"action"`
	}
	type subnetOutput struct {
		ID string `json:"id"`
	}
	type vnetRuleOutput struct {
		Subnet                           subnetOutput `json:"subnet"`
		IgnoreMissingVNetServiceEndpoint bool         `json:"ignoreMissingVnetServiceEndpoint"`
	}
	type networkRuleSetOutput struct {
		ID                          string           `json:"id"`
		Location                    string           `json:"location"`
		Name                        string           `json:"name"`
		ResourceGroup               string           `json:"resourceGroup"`
		Type                        string           `json:"type"`
		DefaultAction               string           `json:"defaultAction"`
		IPRules                     []ipRuleOutput   `json:"ipRules"`
		VirtualNetworkRules         []vnetRuleOutput `json:"virtualNetworkRules"`
		TrustedServiceAccessEnabled bool             `json:"trustedServiceAccessEnabled"`
		PublicNetworkAccess         string           `json:"publicNetworkAccess"`
	}

	out := networkRuleSetOutput{
		Type:                "Microsoft.ServiceBus/namespaces/networkRuleSets",
		PublicNetworkAccess: "Enabled",
	}

	if rules.ID != nil {
		out.ID = *rules.ID
		parts := strings.Split(out.ID, "/")
		for i, part := range parts {
			if part == "resourceGroups" && i+1 < len(parts) {
				out.ResourceGroup = parts[i+1]
				break
			}
		}
	}
	if rules.Name != nil {
		out.Name = *rules.Name
	}
	if rules.Location != nil {
		out.Location = *rules.Location
	}

	if rules.Properties != nil {
		if rules.Properties.DefaultAction != nil {
			out.DefaultAction = string(*rules.Properties.DefaultAction)
		}
		if rules.Properties.TrustedServiceAccessEnabled != nil {
			out.TrustedServiceAccessEnabled = *rules.Properties.TrustedServiceAccessEnabled
		}
		if rules.Properties.PublicNetworkAccess != nil {
			out.PublicNetworkAccess = string(*rules.Properties.PublicNetworkAccess)
		}
		for _, ipRule := range rules.Properties.IPRules {
			if ipRule == nil {
				continue
			}
			r := ipRuleOutput{Action: "Allow"}
			if ipRule.IPMask != nil {
				r.IPMask = *ipRule.IPMask
			}
			if ipRule.Action != nil {
				r.Action = string(*ipRule.Action)
			}
			out.IPRules = append(out.IPRules, r)
		}
		for _, vnetRule := range rules.Properties.VirtualNetworkRules {
			if vnetRule == nil {
				continue
			}
			r := vnetRuleOutput{}
			if vnetRule.Subnet != nil && vnetRule.Subnet.ID != nil {
				r.Subnet.ID = *vnetRule.Subnet.ID
			}
			if vnetRule.IgnoreMissingVnetServiceEndpoint != nil {
				r.IgnoreMissingVNetServiceEndpoint = *vnetRule.IgnoreMissingVnetServiceEndpoint
			}
			out.VirtualNetworkRules = append(out.VirtualNetworkRules, r)
		}
	}

	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error formatting output: %s", err.Error())
	}
	return string(b)
}
