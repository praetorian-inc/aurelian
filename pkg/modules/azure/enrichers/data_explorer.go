package enrichers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/kusto/armkusto/v2"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("data_explorer_public_access", enrichDataExplorer)
}

func enrichDataExplorer(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	clusterName := result.ResourceName
	if clusterName == "" {
		return nil, nil
	}

	// Extract URI from properties if available, otherwise construct
	var clusterURI string
	if result.Properties != nil {
		if uri, ok := result.Properties["uri"].(string); ok && uri != "" {
			clusterURI = strings.TrimSuffix(uri, "/")
		}
	}
	if clusterURI == "" {
		clusterURI = fmt.Sprintf("https://%s.%s.kusto.windows.net", clusterName, result.Location)
	}

	client := NewHTTPClient(10 * time.Second)
	var commands []plugin.AzureEnrichmentCommand

	// Test 1: Data Explorer cluster endpoint accessibility
	curlMain := fmt.Sprintf("curl -i '%s' --max-time 10", clusterURI)
	commands = append(commands, HTTPProbe(client, clusterURI, curlMain,
		"Test if Data Explorer cluster endpoint is accessible",
		"401 = requires Azure AD authentication | 403 = forbidden | 200 = accessible (unusual)",
	))

	// Test 2: Data Explorer management endpoint
	mgmtURL := fmt.Sprintf("%s/v1/rest/mgmt", clusterURI)
	curlMgmt := fmt.Sprintf("curl -i '%s/v1/rest/mgmt' --max-time 10", clusterURI)
	commands = append(commands, HTTPProbe(client, mgmtURL, curlMgmt,
		"Test Data Explorer management endpoint",
		"401 = requires authentication | 403 = forbidden | 200 = management accessible",
	))

	// Test 3: Retrieve Data Explorer cluster network rules via SDK
	subscriptionID := result.SubscriptionID
	resourceGroup := ParseResourceGroup(result.ResourceID)
	networkCmd := getDataExplorerNetworkRulesCommand(cfg, subscriptionID, resourceGroup, clusterName)
	commands = append(commands, networkCmd)

	return commands, nil
}

func getDataExplorerNetworkRulesCommand(cfg plugin.AzureEnricherConfig, subscriptionID, resourceGroup, clusterName string) plugin.AzureEnrichmentCommand {
	azCommand := fmt.Sprintf("az kusto cluster show --name %s --resource-group %s --query '{publicNetworkAccess:properties.publicNetworkAccess,allowedIpRangeList:properties.allowedIpRangeList,publicIPType:properties.publicIPType,enableAutoStop:properties.enableAutoStop,state:properties.state}'", clusterName, resourceGroup)

	if clusterName == "" || subscriptionID == "" || resourceGroup == "" {
		return plugin.AzureEnrichmentCommand{
			Command:      azCommand,
			Description:  "Retrieve Data Explorer cluster network rules",
			ActualOutput: "Error: Cluster name, subscription ID, or resource group is missing",
			ExitCode:     1,
		}
	}

	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	kustoClient, err := armkusto.NewClustersClient(subscriptionID, cfg.Credential, nil)
	if err != nil {
		return plugin.AzureEnrichmentCommand{
			Command:      azCommand,
			Description:  "Retrieve Data Explorer cluster network rules (SDK failed)",
			ActualOutput: fmt.Sprintf("SDK retrieval failed: %s", err.Error()),
			Error:        err.Error(),
			ExitCode:     1,
		}
	}

	response, err := kustoClient.Get(ctx, resourceGroup, clusterName, nil)
	if err != nil {
		return plugin.AzureEnrichmentCommand{
			Command:      azCommand,
			Description:  "Retrieve Data Explorer cluster network rules (SDK failed)",
			ActualOutput: fmt.Sprintf("SDK retrieval failed: %s", err.Error()),
			Error:        err.Error(),
			ExitCode:     1,
		}
	}

	output := formatDataExplorerNetworkRules(&response.Cluster)

	return plugin.AzureEnrichmentCommand{
		Command:                   azCommand,
		Description:               "Retrieve Data Explorer cluster network rules",
		ExpectedOutputDescription: "Network configuration showing public access status and IP restrictions",
		ActualOutput:              output,
		ExitCode:                  0,
	}
}

func formatDataExplorerNetworkRules(cluster *armkusto.Cluster) string {
	if cluster == nil || cluster.Properties == nil {
		return "null"
	}

	type kustoNetworkRulesOutput struct {
		PublicNetworkAccess string   `json:"publicNetworkAccess"`
		AllowedIPRangeList  []string `json:"allowedIpRangeList"`
		PublicIPType        string   `json:"publicIPType,omitempty"`
		EnableAutoStop      bool     `json:"enableAutoStop"`
		State               string   `json:"state"`
	}

	out := kustoNetworkRulesOutput{
		AllowedIPRangeList: []string{},
	}

	props := cluster.Properties
	if props.PublicNetworkAccess != nil {
		out.PublicNetworkAccess = string(*props.PublicNetworkAccess)
	}
	if props.AllowedIPRangeList != nil {
		for _, ipRange := range props.AllowedIPRangeList {
			if ipRange != nil {
				out.AllowedIPRangeList = append(out.AllowedIPRangeList, *ipRange)
			}
		}
	}
	if props.PublicIPType != nil {
		out.PublicIPType = string(*props.PublicIPType)
	}
	if props.EnableAutoStop != nil {
		out.EnableAutoStop = *props.EnableAutoStop
	}
	if props.State != nil {
		out.State = string(*props.State)
	}

	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error formatting output: %s", err.Error())
	}
	return string(b)
}
