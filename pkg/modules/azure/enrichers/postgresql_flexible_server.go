package enrichers

import (
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("postgresql_flexible_server_public_access", enrichPostgreSQLFlexibleServer)
}

func enrichPostgreSQLFlexibleServer(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	serverName := result.ResourceName
	if serverName == "" {
		return nil, nil
	}

	subscriptionID := result.SubscriptionID
	resourceGroup := ParseResourceGroup(result.ResourceID)

	postgresServerFQDN := fmt.Sprintf("%s.postgres.database.azure.com", serverName)

	var commands []plugin.AzureEnrichmentCommand

	// Test 1: TCP connectivity to PostgreSQL port 5432
	commands = append(commands, TCPProbe(postgresServerFQDN, 5432, 10*time.Second))

	// Test 2: Retrieve PostgreSQL Flexible Server firewall rules via SDK
	firewallCmd := getPostgreSQLFirewallRulesCommand(cfg, subscriptionID, resourceGroup, serverName)
	commands = append(commands, firewallCmd)

	return commands, nil
}

func getPostgreSQLFirewallRulesCommand(cfg plugin.AzureEnricherConfig, subscriptionID, resourceGroup, serverName string) plugin.AzureEnrichmentCommand {
	azCommand := fmt.Sprintf("az postgres flexible-server firewall-rule list --resource-group %s --server-name %s", resourceGroup, serverName)
	description := "Retrieve PostgreSQL Flexible Server firewall rules"

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
		firewallClient, err := armpostgresqlflexibleservers.NewFirewallRulesClient(subscriptionID, cfg.Credential, nil)
		if err != nil {
			return nil, err
		}

		pager := firewallClient.NewListByServerPager(resourceGroup, serverName, nil)
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
					Type:           "Microsoft.DBforPostgreSQL/flexibleServers/firewallRules",
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
