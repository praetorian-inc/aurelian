package enricher

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysqlflexibleservers"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql/v2"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

type DatabaseAllowAzureServicesEnricher struct{}

func (d *DatabaseAllowAzureServicesEnricher) CanEnrich(templateID string) bool {
	return templateID == "databases_allow_azure_services"
}

func (d *DatabaseAllowAzureServicesEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	resourceType := strings.ToLower(string(resource.ResourceType))
	switch resourceType {
	case "microsoft.sql/servers", "microsoft.synapse/workspaces":
		commands = append(commands, d.checkSQLServerFirewall(ctx, resource)...)
	case "microsoft.dbforpostgresql/flexibleservers":
		commands = append(commands, d.checkPostgreSQLFirewall(ctx, resource)...)
	case "microsoft.dbformysql/flexibleservers":
		commands = append(commands, d.checkMySQLFirewall(ctx, resource)...)
	}

	return commands
}

func (d *DatabaseAllowAzureServicesEnricher) checkSQLServerFirewall(ctx context.Context, resource *model.AzureResource) []Command {
	serverName := resource.Name
	subscriptionID := resource.AccountRef
	resourceGroupName := resource.ResourceGroup

	if serverName == "" || subscriptionID == "" || resourceGroupName == "" {
		return []Command{{
			Command:      "",
			Description:  "Check SQL Server for AllowAllWindowsAzureIps firewall rule",
			ActualOutput: "Error: Server name, subscription ID, or resource group is missing",
			ExitCode:     1,
		}}
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return []Command{{
			Command:      "",
			Description:  "Check SQL Server for AllowAllWindowsAzureIps firewall rule",
			ActualOutput: fmt.Sprintf("Error getting Azure credentials: %s", err.Error()),
			ExitCode:     1,
		}}
	}

	clientFactory, err := armsql.NewClientFactory(subscriptionID, cred, nil)
	if err != nil {
		return []Command{{
			Command:      "",
			Description:  "Check SQL Server for AllowAllWindowsAzureIps firewall rule",
			ActualOutput: fmt.Sprintf("Error creating client factory: %s", err.Error()),
			ExitCode:     1,
		}}
	}

	firewallClient := clientFactory.NewFirewallRulesClient()

	pager := firewallClient.NewListByServerPager(resourceGroupName, serverName, nil)
	var hasAllowAzureRule bool
	var ruleDetails string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return []Command{{
				Command:      "",
				Description:  "Check SQL Server for AllowAllWindowsAzureIps firewall rule",
				ActualOutput: fmt.Sprintf("Error retrieving firewall rules: %s", err.Error()),
				ExitCode:     1,
			}}
		}

		for _, rule := range page.Value {
			if rule != nil && rule.Name != nil && *rule.Name == "AllowAllWindowsAzureIps" {
				hasAllowAzureRule = true
				if rule.Properties != nil {
					startIP := ""
					endIP := ""
					if rule.Properties.StartIPAddress != nil {
						startIP = *rule.Properties.StartIPAddress
					}
					if rule.Properties.EndIPAddress != nil {
						endIP = *rule.Properties.EndIPAddress
					}
					ruleDetails = fmt.Sprintf("Rule found: %s (%s-%s)", *rule.Name, startIP, endIP)
				}
				break
			}
		}
		if hasAllowAzureRule {
			break
		}
	}

	var output string
	var exitCode int
	if hasAllowAzureRule {
		output = fmt.Sprintf("FINDING: Allow Azure services enabled - %s", ruleDetails)
		exitCode = 1
	} else {
		output = "OK: Allow Azure services disabled - AllowAllWindowsAzureIps rule not found"
		exitCode = 0
	}

	return []Command{{
		Command:      "",
		Description:  "Check SQL Server for AllowAllWindowsAzureIps firewall rule",
		ActualOutput: output,
		ExitCode:     exitCode,
	}}
}

func (d *DatabaseAllowAzureServicesEnricher) checkPostgreSQLFirewall(ctx context.Context, resource *model.AzureResource) []Command {
	serverName := resource.Name
	subscriptionID := resource.AccountRef
	resourceGroupName := resource.ResourceGroup

	if serverName == "" || subscriptionID == "" || resourceGroupName == "" {
		return []Command{{
			Command:      "",
			Description:  "Check PostgreSQL Flexible Server for AllowAllAzureIps rule and public access",
			ActualOutput: "Error: Server name, subscription ID, or resource group is missing",
			ExitCode:     1,
		}}
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return []Command{{
			Command:      "",
			Description:  "Check PostgreSQL Flexible Server for AllowAllAzureIps rule and public access",
			ActualOutput: fmt.Sprintf("Error getting Azure credentials: %s", err.Error()),
			ExitCode:     1,
		}}
	}

	serversClient, err := armpostgresqlflexibleservers.NewServersClient(subscriptionID, cred, nil)
	if err != nil {
		return []Command{{
			Command:      "",
			Description:  "Check PostgreSQL Flexible Server for AllowAllAzureIps rule and public access",
			ActualOutput: fmt.Sprintf("Error creating servers client: %s", err.Error()),
			ExitCode:     1,
		}}
	}

	serverResp, err := serversClient.Get(ctx, resourceGroupName, serverName, nil)
	if err != nil {
		return []Command{{
			Command:      "",
			Description:  "Check PostgreSQL Flexible Server for AllowAllAzureIps rule and public access",
			ActualOutput: fmt.Sprintf("Error getting server details: %s", err.Error()),
			ExitCode:     1,
		}}
	}

	var publicAccessEnabled bool
	if serverResp.Properties != nil && serverResp.Properties.Network != nil && serverResp.Properties.Network.PublicNetworkAccess != nil {
		publicAccessEnabled = *serverResp.Properties.Network.PublicNetworkAccess == armpostgresqlflexibleservers.ServerPublicNetworkAccessStateEnabled
	}

	firewallClient, err := armpostgresqlflexibleservers.NewFirewallRulesClient(subscriptionID, cred, nil)
	if err != nil {
		return []Command{{
			Command:      "",
			Description:  "Check PostgreSQL Flexible Server for AllowAllAzureIps rule and public access",
			ActualOutput: fmt.Sprintf("Error creating firewall client: %s", err.Error()),
			ExitCode:     1,
		}}
	}

	pager := firewallClient.NewListByServerPager(resourceGroupName, serverName, nil)
	var hasAllowAzureRule bool
	var ruleDetails string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return []Command{{
				Command:      "",
				Description:  "Check PostgreSQL Flexible Server for AllowAllAzureIps rule and public access",
				ActualOutput: fmt.Sprintf("Error retrieving firewall rules: %s", err.Error()),
				ExitCode:     1,
			}}
		}

		for _, rule := range page.Value {
			if rule != nil && rule.Name != nil && *rule.Name == "AllowAllAzureIps" {
				hasAllowAzureRule = true
				if rule.Properties != nil {
					startIP := ""
					endIP := ""
					if rule.Properties.StartIPAddress != nil {
						startIP = *rule.Properties.StartIPAddress
					}
					if rule.Properties.EndIPAddress != nil {
						endIP = *rule.Properties.EndIPAddress
					}
					ruleDetails = fmt.Sprintf("Rule found: %s (%s-%s)", *rule.Name, startIP, endIP)
				}
				break
			}
		}
		if hasAllowAzureRule {
			break
		}
	}

	var output string
	var exitCode int
	if hasAllowAzureRule && publicAccessEnabled {
		output = fmt.Sprintf("FINDING: Allow Azure services enabled - %s with public access enabled", ruleDetails)
		exitCode = 1
	} else if hasAllowAzureRule && !publicAccessEnabled {
		output = fmt.Sprintf("OK: Allow Azure services rule exists but public access disabled - %s", ruleDetails)
		exitCode = 0
	} else {
		output = "OK: Allow Azure services disabled - AllowAllAzureIps rule not found"
		exitCode = 0
	}

	return []Command{{
		Command:      "",
		Description:  "Check PostgreSQL Flexible Server for AllowAllAzureIps rule and public access",
		ActualOutput: output,
		ExitCode:     exitCode,
	}}
}

func (d *DatabaseAllowAzureServicesEnricher) checkMySQLFirewall(ctx context.Context, resource *model.AzureResource) []Command {
	serverName := resource.Name
	subscriptionID := resource.AccountRef
	resourceGroupName := resource.ResourceGroup

	if serverName == "" || subscriptionID == "" || resourceGroupName == "" {
		return []Command{{
			Command:      "",
			Description:  "Check MySQL Flexible Server for AllowAllAzureIps rule and public access",
			ActualOutput: "Error: Server name, subscription ID, or resource group is missing",
			ExitCode:     1,
		}}
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return []Command{{
			Command:      "",
			Description:  "Check MySQL Flexible Server for AllowAllAzureIps rule and public access",
			ActualOutput: fmt.Sprintf("Error getting Azure credentials: %s", err.Error()),
			ExitCode:     1,
		}}
	}

	clientFactory, err := armmysqlflexibleservers.NewClientFactory(subscriptionID, cred, nil)
	if err != nil {
		return []Command{{
			Command:      "",
			Description:  "Check MySQL Flexible Server for AllowAllAzureIps rule and public access",
			ActualOutput: fmt.Sprintf("Error creating client factory: %s", err.Error()),
			ExitCode:     1,
		}}
	}

	serversClient := clientFactory.NewServersClient()

	serverResp, err := serversClient.Get(ctx, resourceGroupName, serverName, nil)
	if err != nil {
		return []Command{{
			Command:      "",
			Description:  "Check MySQL Flexible Server for AllowAllAzureIps rule and public access",
			ActualOutput: fmt.Sprintf("Error getting server details: %s", err.Error()),
			ExitCode:     1,
		}}
	}

	var publicAccessEnabled bool
	if serverResp.Properties != nil && serverResp.Properties.Network != nil && serverResp.Properties.Network.PublicNetworkAccess != nil {
		publicAccessEnabled = *serverResp.Properties.Network.PublicNetworkAccess == armmysqlflexibleservers.EnableStatusEnumEnabled
	}

	firewallClient := clientFactory.NewFirewallRulesClient()
	pager := firewallClient.NewListByServerPager(resourceGroupName, serverName, nil)
	var hasAllowAzureRule bool
	var ruleDetails string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return []Command{{
				Command:      "",
				Description:  "Check MySQL Flexible Server for AllowAllAzureIps rule and public access",
				ActualOutput: fmt.Sprintf("Error retrieving firewall rules: %s", err.Error()),
				ExitCode:     1,
			}}
		}

		for _, rule := range page.Value {
			if rule != nil && rule.Name != nil && *rule.Name == "AllowAllAzureIps" {
				hasAllowAzureRule = true
				if rule.Properties != nil {
					startIP := ""
					endIP := ""
					if rule.Properties.StartIPAddress != nil {
						startIP = *rule.Properties.StartIPAddress
					}
					if rule.Properties.EndIPAddress != nil {
						endIP = *rule.Properties.EndIPAddress
					}
					ruleDetails = fmt.Sprintf("Rule found: %s (%s-%s)", *rule.Name, startIP, endIP)
				}
				break
			}
		}
		if hasAllowAzureRule {
			break
		}
	}

	var output string
	var exitCode int
	if hasAllowAzureRule && publicAccessEnabled {
		output = fmt.Sprintf("FINDING: Allow Azure services enabled - %s with public access enabled", ruleDetails)
		exitCode = 1
	} else if hasAllowAzureRule && !publicAccessEnabled {
		output = fmt.Sprintf("OK: Allow Azure services rule exists but public access disabled - %s", ruleDetails)
		exitCode = 0
	} else {
		output = "OK: Allow Azure services disabled - AllowAllAzureIps rule not found"
		exitCode = 0
	}

	return []Command{{
		Command:      "",
		Description:  "Check MySQL Flexible Server for AllowAllAzureIps rule and public access",
		ActualOutput: output,
		ExitCode:     exitCode,
	}}
}