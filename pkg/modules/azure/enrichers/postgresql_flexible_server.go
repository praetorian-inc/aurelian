package enrichers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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

	if serverName == "" || subscriptionID == "" || resourceGroup == "" {
		return plugin.AzureEnrichmentCommand{
			Command:      azCommand,
			Description:  "Retrieve PostgreSQL Flexible Server firewall rules",
			ActualOutput: "Error: Server name, subscription ID, or resource group is missing",
			ExitCode:     1,
		}
	}

	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	firewallClient, err := armpostgresqlflexibleservers.NewFirewallRulesClient(subscriptionID, cfg.Credential, nil)
	if err != nil {
		return plugin.AzureEnrichmentCommand{
			Command:      azCommand,
			Description:  "Retrieve PostgreSQL Flexible Server firewall rules (SDK failed)",
			ActualOutput: fmt.Sprintf("SDK retrieval failed: %s", err.Error()),
			Error:        err.Error(),
			ExitCode:     1,
		}
	}

	pager := firewallClient.NewListByServerPager(resourceGroup, serverName, nil)

	type pgFirewallRuleOutput struct {
		EndIPAddress   string `json:"endIpAddress"`
		ID             string `json:"id"`
		Name           string `json:"name"`
		ResourceGroup  string `json:"resourceGroup"`
		StartIPAddress string `json:"startIpAddress"`
		Type           string `json:"type"`
	}

	var outputRules []pgFirewallRuleOutput
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return plugin.AzureEnrichmentCommand{
				Command:      azCommand,
				Description:  "Retrieve PostgreSQL Flexible Server firewall rules (SDK failed)",
				ActualOutput: fmt.Sprintf("SDK retrieval failed: %s", err.Error()),
				Error:        err.Error(),
				ExitCode:     1,
			}
		}
		for _, rule := range page.Value {
			if rule == nil {
				continue
			}
			o := pgFirewallRuleOutput{Type: "Microsoft.DBforPostgreSQL/flexibleServers/firewallRules"}
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
		Description:               "Retrieve PostgreSQL Flexible Server firewall rules",
		ExpectedOutputDescription: "List of firewall rules with names and IP address ranges",
		ActualOutput:              output,
		ExitCode:                  0,
	}
}
