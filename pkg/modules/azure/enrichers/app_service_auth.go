package enrichers

import (
	"log/slog"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v4"

	"github.com/praetorian-inc/aurelian/pkg/azure/enrichment"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("microsoft.web/sites", enrichAppServiceAuth)
}

func enrichAppServiceAuth(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) error {
	subID, rg, name, err := enrichment.ParseResource(*result)
	if err != nil {
		return err
	}

	client, err := armappservice.NewWebAppsClient(subID, cfg.Credential, nil)
	if err != nil {
		return err
	}

	authSettings, err := client.GetAuthSettingsV2(cfg.Context, rg, name, nil)
	if err != nil {
		slog.Warn("could not get auth settings, skipping",
			"resource", result.ResourceID, "error", err)
		return nil
	}

	enabled := false
	if authSettings.Properties != nil &&
		authSettings.Properties.Platform != nil &&
		authSettings.Properties.Platform.Enabled != nil {
		enabled = *authSettings.Properties.Platform.Enabled
	}

	result.Properties["authEnabled"] = enabled
	return nil
}
