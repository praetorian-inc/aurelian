package enrichers

import (
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysqlflexibleservers"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers"
	armsql "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql/v2"

	"github.com/praetorian-inc/aurelian/pkg/azure/enrichment"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("microsoft.sql/servers", enrichDatabaseFirewall)
	plugin.RegisterAzureEnricher("microsoft.synapse/workspaces", enrichDatabaseFirewall)
	plugin.RegisterAzureEnricher("microsoft.dbforpostgresql/flexibleservers", enrichDatabaseFirewall)
	plugin.RegisterAzureEnricher("microsoft.dbformysql/flexibleservers", enrichDatabaseFirewall)
}

func enrichDatabaseFirewall(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) error {
	subID, rg, name, err := enrichment.ParseResource(*result)
	if err != nil {
		return err
	}

	found, err := checkFirewallRules(cfg, subID, rg, name, result.ResourceType)
	if err != nil {
		return err
	}

	result.Properties["allowAzureServicesFirewall"] = found
	return nil
}

func checkFirewallRules(cfg plugin.AzureEnricherConfig, subID, rg, name, resourceType string) (bool, error) {
	lower := strings.ToLower(resourceType)
	switch {
	case strings.Contains(lower, "microsoft.sql/servers"),
		strings.Contains(lower, "microsoft.synapse"):
		return checkSQLFirewall(cfg, subID, rg, name)
	case strings.Contains(lower, "microsoft.dbforpostgresql"):
		return checkPostgreSQLFirewall(cfg, subID, rg, name)
	case strings.Contains(lower, "microsoft.dbformysql"):
		return checkMySQLFirewall(cfg, subID, rg, name)
	default:
		return false, fmt.Errorf("unsupported database type: %s", resourceType)
	}
}

func checkSQLFirewall(cfg plugin.AzureEnricherConfig, subID, rg, serverName string) (bool, error) {
	factory, err := armsql.NewClientFactory(subID, cfg.Credential, nil)
	if err != nil {
		return false, fmt.Errorf("creating SQL client: %w", err)
	}

	pager := factory.NewFirewallRulesClient().NewListByServerPager(rg, serverName, nil)
	for pager.More() {
		page, err := pager.NextPage(cfg.Context)
		if err != nil {
			return false, fmt.Errorf("listing SQL firewall rules: %w", err)
		}
		for _, rule := range page.Value {
			if rule.Properties == nil {
				continue
			}
			if isAllowAzureServicesRule(derefStr(rule.Properties.StartIPAddress), derefStr(rule.Properties.EndIPAddress)) {
				return true, nil
			}
		}
	}
	return false, nil
}

func checkPostgreSQLFirewall(cfg plugin.AzureEnricherConfig, subID, rg, serverName string) (bool, error) {
	client, err := armpostgresqlflexibleservers.NewFirewallRulesClient(subID, cfg.Credential, nil)
	if err != nil {
		return false, fmt.Errorf("creating PostgreSQL firewall client: %w", err)
	}

	pager := client.NewListByServerPager(rg, serverName, nil)
	for pager.More() {
		page, err := pager.NextPage(cfg.Context)
		if err != nil {
			return false, fmt.Errorf("listing PostgreSQL firewall rules: %w", err)
		}
		for _, rule := range page.Value {
			var start, end string
			if rule.Properties != nil {
				start, end = derefStr(rule.Properties.StartIPAddress), derefStr(rule.Properties.EndIPAddress)
			}
			if isFlexibleServerAllowAllAzureRule(rule.Name, start, end) {
				return true, nil
			}
		}
	}
	return false, nil
}

func checkMySQLFirewall(cfg plugin.AzureEnricherConfig, subID, rg, serverName string) (bool, error) {
	factory, err := armmysqlflexibleservers.NewClientFactory(subID, cfg.Credential, nil)
	if err != nil {
		return false, fmt.Errorf("creating MySQL client: %w", err)
	}

	pager := factory.NewFirewallRulesClient().NewListByServerPager(rg, serverName, nil)
	for pager.More() {
		page, err := pager.NextPage(cfg.Context)
		if err != nil {
			return false, fmt.Errorf("listing MySQL firewall rules: %w", err)
		}
		for _, rule := range page.Value {
			var start, end string
			if rule.Properties != nil {
				start, end = derefStr(rule.Properties.StartIPAddress), derefStr(rule.Properties.EndIPAddress)
			}
			if isFlexibleServerAllowAllAzureRule(rule.Name, start, end) {
				return true, nil
			}
		}
	}
	return false, nil
}

// isFlexibleServerAllowAllAzureRule checks if a flexible server firewall rule
// represents the "Allow Azure Services" rule, by well-known name or IP range.
func isFlexibleServerAllowAllAzureRule(name *string, startIP, endIP string) bool {
	if name != nil && *name == "AllowAllAzureIps" {
		return true
	}
	return isAllowAzureServicesRule(startIP, endIP)
}

func isAllowAzureServicesRule(startIP, endIP string) bool {
	return startIP == "0.0.0.0" && endIP == "0.0.0.0"
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
