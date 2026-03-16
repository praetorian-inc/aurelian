package enrichers

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"

	"github.com/praetorian-inc/aurelian/pkg/azure/enrichment"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("app_service_remote_debugging_enabled", checkRemoteDebugging)
}

func checkRemoteDebugging(cfg plugin.AzureEnricherConfig, result templates.ARGQueryResult) (bool, error) {
	subID, rg, name, err := enrichment.ParseResource(result)
	if err != nil {
		return false, err
	}

	client, err := armappservice.NewWebAppsClient(subID, cfg.Credential, nil)
	if err != nil {
		return false, fmt.Errorf("creating web apps client: %w", err)
	}

	config, err := client.GetConfiguration(cfg.Context, rg, name, nil)
	if err != nil {
		return false, fmt.Errorf("getting configuration for %s: %w", name, err)
	}

	if config.Properties != nil &&
		config.Properties.RemoteDebuggingEnabled != nil &&
		*config.Properties.RemoteDebuggingEnabled {
		return true, nil
	}

	return false, nil
}
