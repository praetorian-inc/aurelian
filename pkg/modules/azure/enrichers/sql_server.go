package enrichers

import (
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql/v2"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("sql_servers_public_access", enrichSQLServer)
}

func enrichSQLServer(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	serverName := result.ResourceName
	if serverName == "" {
		return nil, nil
	}

	subscriptionID := result.SubscriptionID
	resourceGroup := ParseResourceGroup(result.ResourceID)

	sqlServerFQDN := fmt.Sprintf("%s.database.windows.net", serverName)

	var commands []plugin.AzureEnrichmentCommand

	// Test 1: TCP connectivity to SQL Server port 1433
	commands = append(commands, TCPProbe(sqlServerFQDN, 1433, 10*time.Second))

	// Test 2: Retrieve SQL Server firewall rules via SDK
	firewallCmd := getSQLFirewallRulesCommand(cfg, subscriptionID, resourceGroup, serverName)
	commands = append(commands, firewallCmd)

	return commands, nil
}

func getSQLFirewallRulesCommand(cfg plugin.AzureEnricherConfig, subscriptionID, resourceGroup, serverName string) plugin.AzureEnrichmentCommand {
	azCommand := fmt.Sprintf("az sql server firewall-rule list --resource-group %s --server %s", resourceGroup, serverName)
	description := "Retrieve SQL Server firewall rules"

	if serverName == "" || subscriptionID == "" || resourceGroup == "" {
		return plugin.AzureEnrichmentCommand{
			Command:      azCommand,
			Description:  description,
			ActualOutput: "Error: Server name, subscription ID, or resource group is missing",
			ExitCode:     1,
		}
	}

	ctx := cfg.Context

	return buildFirewallRulesCommand(azCommand, description, func() ([]firewallRuleOutput, error) {
		clientFactory, err := armsql.NewClientFactory(subscriptionID, cfg.Credential, nil)
		if err != nil {
			return nil, err
		}

		pager := clientFactory.NewFirewallRulesClient().NewListByServerPager(resourceGroup, serverName, nil)
		var rules []firewallRuleOutput
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, rule := range page.Value {
				if rule == nil || rule.Properties == nil {
					continue
				}
				rules = append(rules, firewallRuleOutput{
					Type:           "Microsoft.Sql/servers/firewallRules",
					Name:           derefString(rule.Name),
					ID:             derefString(rule.ID),
					ResourceGroup:  ParseResourceGroup(derefString(rule.ID)),
					StartIPAddress: derefString(rule.Properties.StartIPAddress),
					EndIPAddress:   derefString(rule.Properties.EndIPAddress),
				})
			}
		}
		return rules, nil
	})
}
