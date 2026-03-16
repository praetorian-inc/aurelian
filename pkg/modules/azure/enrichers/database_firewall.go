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
	plugin.RegisterAzureEnricher("databases_allow_azure_services", checkDatabaseFirewall)
}

func checkDatabaseFirewall(cfg plugin.AzureEnricherConfig, result templates.ARGQueryResult) (bool, error) {
	subID, rg, name, err := enrichment.ParseResource(result)
	if err != nil {
		return false, err
	}

	resourceType := strings.ToLower(result.ResourceType)
	switch {
	case strings.Contains(resourceType, "microsoft.sql/servers"),
		strings.Contains(resourceType, "microsoft.synapse"):
		return checkSQLFirewall(cfg, subID, rg, name)
	case strings.Contains(resourceType, "microsoft.dbforpostgresql"):
		return checkPostgreSQLFirewall(cfg, subID, rg, name)
	case strings.Contains(resourceType, "microsoft.dbformysql"):
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
			if rule.Name != nil && *rule.Name == "AllowAllAzureIps" {
				return true, nil
			}
			if rule.Properties != nil && isAllowAzureServicesRule(derefStr(rule.Properties.StartIPAddress), derefStr(rule.Properties.EndIPAddress)) {
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
			if rule.Name != nil && *rule.Name == "AllowAllAzureIps" {
				return true, nil
			}
			if rule.Properties != nil && isAllowAzureServicesRule(derefStr(rule.Properties.StartIPAddress), derefStr(rule.Properties.EndIPAddress)) {
				return true, nil
			}
		}
	}
	return false, nil
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
