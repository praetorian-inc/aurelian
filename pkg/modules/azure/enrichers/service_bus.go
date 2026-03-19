package enrichers

import (
	"context"
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

	return buildNetworkRulesCommand(
		cfg, azCommand,
		"Retrieve Service Bus namespace network rules",
		"Network rule configuration with default action and IP/VNet rules",
		"Error: Namespace name, subscription ID, or resource group is missing",
		[]string{namespaceName, subscriptionID, resourceGroup},
		func(ctx context.Context) (string, error) {
			clientFactory, err := armservicebus.NewClientFactory(subscriptionID, cfg.Credential, nil)
			if err != nil {
				return "", err
			}
			namespacesClient := clientFactory.NewNamespacesClient()
			response, err := namespacesClient.GetNetworkRuleSet(ctx, resourceGroup, namespaceName, nil)
			if err != nil {
				return "", err
			}
			return formatServiceBusNetworkRules(&response.NetworkRuleSet), nil
		},
	)
}

func formatServiceBusNetworkRules(rules *armservicebus.NetworkRuleSet) string {
	if rules == nil {
		return "null"
	}

	input := &networkRuleSetInput{
		ID:       rules.ID,
		Name:     rules.Name,
		Location: rules.Location,
	}

	if rules.Properties != nil {
		if rules.Properties.DefaultAction != nil {
			s := string(*rules.Properties.DefaultAction)
			input.DefaultAction = &s
		}
		input.TrustedServiceAccessEnabled = rules.Properties.TrustedServiceAccessEnabled
		if rules.Properties.PublicNetworkAccess != nil {
			s := string(*rules.Properties.PublicNetworkAccess)
			input.PublicNetworkAccess = &s
		}
		for _, ipRule := range rules.Properties.IPRules {
			if ipRule == nil {
				continue
			}
			r := networkRuleSetIPRule{IPMask: ipRule.IPMask}
			if ipRule.Action != nil {
				s := string(*ipRule.Action)
				r.Action = &s
			}
			input.IPRules = append(input.IPRules, r)
		}
		for _, vnetRule := range rules.Properties.VirtualNetworkRules {
			if vnetRule == nil {
				continue
			}
			r := networkRuleSetVNetRule{
				IgnoreMissingVnetServiceEndpoint: vnetRule.IgnoreMissingVnetServiceEndpoint,
			}
			if vnetRule.Subnet != nil {
				r.SubnetID = vnetRule.Subnet.ID
			}
			input.VirtualNetworkRules = append(input.VirtualNetworkRules, r)
		}
	}

	return formatNetworkRuleSet(input, "Microsoft.ServiceBus/namespaces/networkRuleSets", "Enabled")
}
