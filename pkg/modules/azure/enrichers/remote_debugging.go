package enrichers

import (
	"log/slog"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v4"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/pkg/azure/enrichment"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("microsoft.web/sites", enrichRemoteDebugging)
}

func enrichRemoteDebugging(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) error {
	subID, rg, name, err := enrichment.ParseResource(*result)
	if err != nil {
		return err
	}

	client, err := armappservice.NewWebAppsClient(subID, cfg.Credential, azurecloud.ARMClientOptions(cfg.Credential))
	if err != nil {
		return err
	}

	config, err := client.GetConfiguration(cfg.Context, rg, name, nil)
	if err != nil {
		slog.Warn("could not get site config, skipping",
			"resource", result.ResourceID, "error", err)
		if azurecloud.ForCredential(cfg.Credential).Name == azurecloud.Government {
			return err
		}
		return nil
	}

	enabled := false
	if config.Properties != nil &&
		config.Properties.RemoteDebuggingEnabled != nil {
		enabled = *config.Properties.RemoteDebuggingEnabled
	}

	result.Properties["remoteDebuggingEnabled"] = enabled
	return nil
}
