package enrichers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysqlflexibleservers"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("mysql_flexible_server_public_access", enrichMySQLFlexibleServer)
}

func enrichMySQLFlexibleServer(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	serverName := result.ResourceName
	if serverName == "" {
		return nil, nil
	}

	subscriptionID := result.SubscriptionID
	resourceGroup := ParseResourceGroup(result.ResourceID)

	mysqlServerFQDN := fmt.Sprintf("%s.mysql.database.azure.com", serverName)

	var commands []plugin.AzureEnrichmentCommand

	// Test 1: TCP connectivity to MySQL port 3306
	commands = append(commands, TCPProbe(mysqlServerFQDN, 3306, 10*time.Second))

	// Test 2: Retrieve MySQL Flexible Server firewall rules via SDK
	firewallCmd := getMySQLFirewallRulesCommand(cfg, subscriptionID, resourceGroup, serverName)
	commands = append(commands, firewallCmd)

	return commands, nil
}

func getMySQLFirewallRulesCommand(cfg plugin.AzureEnricherConfig, subscriptionID, resourceGroup, serverName string) plugin.AzureEnrichmentCommand {
	azCommand := fmt.Sprintf("az mysql flexible-server firewall-rule list --resource-group %s --server-name %s", resourceGroup, serverName)

	if serverName == "" || subscriptionID == "" || resourceGroup == "" {
		return plugin.AzureEnrichmentCommand{
			Command:      azCommand,
			Description:  "Retrieve MySQL Flexible Server firewall rules",
			ActualOutput: "Error: Server name, subscription ID, or resource group is missing",
			ExitCode:     1,
		}
	}

	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	clientFactory, err := armmysqlflexibleservers.NewClientFactory(subscriptionID, cfg.Credential, nil)
	if err != nil {
		return plugin.AzureEnrichmentCommand{
			Command:      azCommand,
			Description:  "Retrieve MySQL Flexible Server firewall rules (SDK failed)",
			ActualOutput: fmt.Sprintf("SDK retrieval failed: %s", err.Error()),
			Error:        err.Error(),
			ExitCode:     1,
		}
	}

	firewallClient := clientFactory.NewFirewallRulesClient()
	pager := firewallClient.NewListByServerPager(resourceGroup, serverName, nil)

	type mysqlFirewallRuleOutput struct {
		EndIPAddress   string `json:"endIpAddress"`
		ID             string `json:"id"`
		Name           string `json:"name"`
		ResourceGroup  string `json:"resourceGroup"`
		StartIPAddress string `json:"startIpAddress"`
		Type           string `json:"type"`
	}

	var outputRules []mysqlFirewallRuleOutput
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return plugin.AzureEnrichmentCommand{
				Command:      azCommand,
				Description:  "Retrieve MySQL Flexible Server firewall rules (SDK failed)",
				ActualOutput: fmt.Sprintf("SDK retrieval failed: %s", err.Error()),
				Error:        err.Error(),
				ExitCode:     1,
			}
		}
		for _, rule := range page.Value {
			if rule == nil {
				continue
			}
			o := mysqlFirewallRuleOutput{Type: "Microsoft.DBforMySQL/flexibleServers/firewallRules"}
			if rule.Name != nil {
				o.Name = *rule.Name
			}
			if rule.ID != nil {
				o.ID = *rule.ID
				parts := strings.Split(o.ID, "/")
				for i, part := range parts {
					if part == "resourceGroups" && i+1 < len(parts) {
						o.ResourceGroup = parts[i+1]
						break
					}
				}
			}
			if rule.Properties != nil {
				if rule.Properties.StartIPAddress != nil {
					o.StartIPAddress = *rule.Properties.StartIPAddress
				}
				if rule.Properties.EndIPAddress != nil {
					o.EndIPAddress = *rule.Properties.EndIPAddress
				}
			}
			outputRules = append(outputRules, o)
		}
	}

	output := "[]"
	if len(outputRules) > 0 {
		b, err := json.MarshalIndent(outputRules, "", "  ")
		if err != nil {
			output = fmt.Sprintf("Error formatting output: %s", err.Error())
		} else {
			output = string(b)
		}
	}

	return plugin.AzureEnrichmentCommand{
		Command:                   azCommand,
		Description:               "Retrieve MySQL Flexible Server firewall rules",
		ExpectedOutputDescription: "List of firewall rules with names and IP address ranges",
		ActualOutput:              output,
		ExitCode:                  0,
	}
}
