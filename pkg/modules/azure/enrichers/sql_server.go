package enrichers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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

	if serverName == "" || subscriptionID == "" || resourceGroup == "" {
		return plugin.AzureEnrichmentCommand{
			Command:      azCommand,
			Description:  "Retrieve SQL Server firewall rules",
			ActualOutput: "Error: Server name, subscription ID, or resource group is missing",
			ExitCode:     1,
		}
	}

	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	clientFactory, err := armsql.NewClientFactory(subscriptionID, cfg.Credential, nil)
	if err != nil {
		return plugin.AzureEnrichmentCommand{
			Command:      azCommand,
			Description:  "Retrieve SQL Server firewall rules (SDK failed)",
			ActualOutput: fmt.Sprintf("SDK retrieval failed: %s", err.Error()),
			Error:        err.Error(),
			ExitCode:     1,
		}
	}

	firewallClient := clientFactory.NewFirewallRulesClient()
	pager := firewallClient.NewListByServerPager(resourceGroup, serverName, nil)

	type firewallRuleOutput struct {
		EndIPAddress   string `json:"endIpAddress"`
		ID             string `json:"id"`
		Name           string `json:"name"`
		ResourceGroup  string `json:"resourceGroup"`
		StartIPAddress string `json:"startIpAddress"`
		Type           string `json:"type"`
	}

	var outputRules []firewallRuleOutput
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return plugin.AzureEnrichmentCommand{
				Command:      azCommand,
				Description:  "Retrieve SQL Server firewall rules (SDK failed)",
				ActualOutput: fmt.Sprintf("SDK retrieval failed: %s", err.Error()),
				Error:        err.Error(),
				ExitCode:     1,
			}
		}
		for _, rule := range page.Value {
			if rule == nil {
				continue
			}
			o := firewallRuleOutput{Type: "Microsoft.Sql/servers/firewallRules"}
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
		Description:               "Retrieve SQL Server firewall rules",
		ExpectedOutputDescription: "List of firewall rules with names and IP address ranges",
		ActualOutput:              output,
		ExitCode:                  0,
	}
}
