package enrichers

import (
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("application_gateway_public_access", enrichApplicationGateway)
}

func enrichApplicationGateway(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	gatewayName := result.ResourceName
	resourceGroup := ParseResourceGroup(result.ResourceID)

	if gatewayName == "" || resourceGroup == "" {
		return nil, nil
	}

	var commands []plugin.AzureEnrichmentCommand

	// Resolve public IP address
	publicIPID, _ := result.Properties["publicIpId"].(string)
	if publicIPID != "" {
		commands = append(commands, plugin.AzureEnrichmentCommand{
			Command:                   fmt.Sprintf("az network public-ip show --ids %s --query ipAddress -o tsv", publicIPID),
			Description:               "Resolve public IP address of Application Gateway",
			ExpectedOutputDescription: "IP address = gateway has public IP | Error = IP not found",
			ActualOutput:              "Manual execution required - requires Azure CLI authentication",
		})
	} else {
		commands = append(commands, plugin.AzureEnrichmentCommand{
			Description:               "Resolve public IP address of Application Gateway",
			ExpectedOutputDescription: "IP address = gateway has public IP | Error = IP not found",
			ActualOutput:              "Error: publicIpId not available in resource properties",
		})
	}

	// Check WAF configuration
	commands = append(commands, plugin.AzureEnrichmentCommand{
		Command:                   fmt.Sprintf("az network application-gateway waf-config show --gateway-name %s --resource-group %s", gatewayName, resourceGroup),
		Description:               "Check Application Gateway WAF configuration",
		ExpectedOutputDescription: "WAF config = WAF is enabled | Error = WAF not configured (higher risk)",
		ActualOutput:              "Manual execution required - requires Azure CLI authentication",
	})

	// CLI fallback
	commands = append(commands, plugin.AzureEnrichmentCommand{
		Command:                   fmt.Sprintf("az network application-gateway show --name %s --resource-group %s", gatewayName, resourceGroup),
		Description:               "Azure CLI command to show Application Gateway details",
		ExpectedOutputDescription: "Gateway details = accessible via Azure API | Error = access denied",
		ActualOutput:              "Manual execution required - requires Azure CLI authentication",
	})

	return commands, nil
}
