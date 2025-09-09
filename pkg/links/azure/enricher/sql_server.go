package enricher

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql/v2"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// SQLServerEnricher implements enrichment for SQL Server instances
type SQLServerEnricher struct{}

func (s *SQLServerEnricher) CanEnrich(templateID string) bool {
	return templateID == "sql_servers_public_access"
}

func (s *SQLServerEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	// Extract SQL Server name and construct FQDN
	serverName := resource.Name
	if serverName == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing SQL Server name",
			ActualOutput: "Error: SQL Server name is empty",
		})
		return commands
	}

	// Construct SQL Server FQDN
	sqlServerFQDN := fmt.Sprintf("%s.database.windows.net", serverName)

	// Test 1: TCP connectivity to SQL Server port 1433
	conn, err := net.DialTimeout("tcp", sqlServerFQDN+":1433", 10*time.Second)

	tcpConnCommand := Command{
		Command:                   fmt.Sprintf("nc -zv %s 1433", sqlServerFQDN),
		Description:               "Test TCP connectivity to SQL Server port 1433",
		ExpectedOutputDescription: "Connection succeeded = accessible | Connection failed/timeout = blocked/firewall rules active",
	}

	if err != nil {
		tcpConnCommand.Error = err.Error()
		tcpConnCommand.ActualOutput = fmt.Sprintf("Connection failed: %s", err.Error())
		tcpConnCommand.ExitCode = 1
	} else {
		conn.Close()
		tcpConnCommand.ActualOutput = "Connection successful - SQL Server port is accessible"
		tcpConnCommand.ExitCode = 0
	}

	commands = append(commands, tcpConnCommand)

	// Test 2: SQL Server connection attempt with username and password
	username := "<USERNAME>"
	password := "<PASSWORD>"

	sqlcmdCommand := fmt.Sprintf("sqlcmd -S %s -U %s -P '%s' -Q 'SELECT @@VERSION' -l 10", sqlServerFQDN, username, password)
	description := fmt.Sprintf("Test SQL connection with credentials '%s:%s'", username, password)

	sqlTestCommand := Command{
		Command:                   sqlcmdCommand,
		Description:               description,
		ExpectedOutputDescription: "Version info = authentication successful | Login failed = invalid credentials | Connection failed = network/access issue",
		ActualOutput:              "Manual execution required - requires sqlcmd tool",
	}

	commands = append(commands, sqlTestCommand)

	// Test 3: Retrieve SQL Server firewall rules
	firewallCommand := s.getFirewallRulesCommand(ctx, resource)
	commands = append(commands, firewallCommand)

	return commands
}

// getFirewallRulesCommand retrieves firewall rules and creates a command with the results
func (s *SQLServerEnricher) getFirewallRulesCommand(ctx context.Context, resource *model.AzureResource) Command {
	serverName := resource.Name
	subscriptionID := resource.AccountRef
	resourceGroupName := resource.ResourceGroup

	azCommand := fmt.Sprintf("az sql server firewall-rule list --resource-group %s --server %s", resourceGroupName, serverName)

	if serverName == "" || subscriptionID == "" || resourceGroupName == "" {
		return Command{
			Command:      azCommand,
			Description:  "Retrieve SQL Server firewall rules",
			ActualOutput: "Error: Server name, subscription ID, or resource group is missing",
			ExitCode:     1,
		}
	}

	// Get firewall rules from Azure SDK
	firewallRules, err := s.retrieveFirewallRules(ctx, subscriptionID, resourceGroupName, serverName)
	if err != nil {
		return Command{
			Command:                   azCommand,
			Description:               "Retrieve SQL Server firewall rules (SDK failed, manual execution required)",
			ExpectedOutputDescription: "List of firewall rules with IP ranges | Error = insufficient permissions or server not found",
			ActualOutput:              fmt.Sprintf("SDK retrieval failed: %s. Manual execution required", err.Error()),
			Error:                     err.Error(),
			ExitCode:                  1,
		}
	}

	// Format output with firewall rules
	output := s.formatFirewallRules(firewallRules)

	return Command{
		Command:                   azCommand,
		Description:               "Retrieve SQL Server firewall rules",
		ExpectedOutputDescription: "List of firewall rules with names and IP address ranges",
		ActualOutput:              output,
		ExitCode:                  0,
	}
}

// retrieveFirewallRules gets firewall rules using Azure SDK
func (s *SQLServerEnricher) retrieveFirewallRules(ctx context.Context, subscriptionID, resourceGroupName, serverName string) ([]armsql.FirewallRule, error) {
	// Get Azure credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure credentials: %w", err)
	}

	// Create SQL client factory
	clientFactory, err := armsql.NewClientFactory(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create client factory: %w", err)
	}

	// Create firewall rules client
	firewallClient := clientFactory.NewFirewallRulesClient()

	// List firewall rules
	pager := firewallClient.NewListByServerPager(resourceGroupName, serverName, nil)
	var rules []armsql.FirewallRule

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get firewall rules: %w", err)
		}

		for _, rule := range page.Value {
			if rule != nil {
				rules = append(rules, *rule)
			}
		}
	}

	return rules, nil
}

// FirewallRuleOutput represents the Azure CLI output format for firewall rules
type FirewallRuleOutput struct {
	EndIPAddress   string `json:"endIpAddress"`
	ID             string `json:"id"`
	Name           string `json:"name"`
	ResourceGroup  string `json:"resourceGroup"`
	StartIPAddress string `json:"startIpAddress"`
	Type           string `json:"type"`
}

// formatFirewallRules formats firewall rules to match Azure CLI JSON output
func (s *SQLServerEnricher) formatFirewallRules(rules []armsql.FirewallRule) string {
	if len(rules) == 0 {
		return "[]"
	}

	var outputRules []FirewallRuleOutput

	for _, rule := range rules {
		outputRule := FirewallRuleOutput{
			Type: "Microsoft.Sql/servers/firewallRules",
		}

		if rule.Name != nil {
			outputRule.Name = *rule.Name
		}
		if rule.ID != nil {
			outputRule.ID = *rule.ID
		}
		if rule.Properties != nil {
			if rule.Properties.StartIPAddress != nil {
				outputRule.StartIPAddress = *rule.Properties.StartIPAddress
			}
			if rule.Properties.EndIPAddress != nil {
				outputRule.EndIPAddress = *rule.Properties.EndIPAddress
			}
		}

		// Extract resource group from ID if available
		if outputRule.ID != "" {
			parts := strings.Split(outputRule.ID, "/")
			for i, part := range parts {
				if part == "resourceGroups" && i+1 < len(parts) {
					outputRule.ResourceGroup = parts[i+1]
					break
				}
			}
		}

		outputRules = append(outputRules, outputRule)
	}

	jsonOutput, err := json.MarshalIndent(outputRules, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error formatting output: %s", err.Error())
	}

	return string(jsonOutput)
}
