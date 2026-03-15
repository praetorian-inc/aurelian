package configscan

import (
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysqlflexibleservers"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers"
	armsql "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql/v2"

	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func (e *Enricher) checkDatabaseFirewall(result templates.ARGQueryResult) (bool, error) {
	subID, rg, name, err := ParseResource(result)
	if err != nil {
		return false, err
	}

	resourceType := strings.ToLower(result.ResourceType)
	switch {
	case strings.Contains(resourceType, "microsoft.sql/servers"),
		strings.Contains(resourceType, "microsoft.synapse"):
		return e.checkSQLFirewall(subID, rg, name)
	case strings.Contains(resourceType, "microsoft.dbforpostgresql"):
		return e.checkPostgreSQLFirewall(subID, rg, name)
	case strings.Contains(resourceType, "microsoft.dbformysql"):
		return e.checkMySQLFirewall(subID, rg, name)
	default:
		return false, fmt.Errorf("unsupported database type: %s", resourceType)
	}
}

func (e *Enricher) checkSQLFirewall(subID, rg, serverName string) (bool, error) {
	factory, err := armsql.NewClientFactory(subID, e.cred, nil)
	if err != nil {
		return false, fmt.Errorf("creating SQL client: %w", err)
	}

	pager := factory.NewFirewallRulesClient().NewListByServerPager(rg, serverName, nil)
	for pager.More() {
		page, err := pager.NextPage(e.ctx)
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

func (e *Enricher) checkPostgreSQLFirewall(subID, rg, serverName string) (bool, error) {
	client, err := armpostgresqlflexibleservers.NewFirewallRulesClient(subID, e.cred, nil)
	if err != nil {
		return false, fmt.Errorf("creating PostgreSQL firewall client: %w", err)
	}

	pager := client.NewListByServerPager(rg, serverName, nil)
	for pager.More() {
		page, err := pager.NextPage(e.ctx)
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

func (e *Enricher) checkMySQLFirewall(subID, rg, serverName string) (bool, error) {
	factory, err := armmysqlflexibleservers.NewClientFactory(subID, e.cred, nil)
	if err != nil {
		return false, fmt.Errorf("creating MySQL client: %w", err)
	}

	pager := factory.NewFirewallRulesClient().NewListByServerPager(rg, serverName, nil)
	for pager.More() {
		page, err := pager.NextPage(e.ctx)
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
