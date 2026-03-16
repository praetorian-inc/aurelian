package enrichers

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"

	"github.com/praetorian-inc/aurelian/pkg/azure/enrichment"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("app_service_auth_disabled", checkAppServiceAuth)
}

func checkAppServiceAuth(cfg plugin.AzureEnricherConfig, result templates.ARGQueryResult) (bool, error) {
	subID, rg, name, err := enrichment.ParseResource(result)
	if err != nil {
		return false, err
	}

	client, err := armappservice.NewWebAppsClient(subID, cfg.Credential, nil)
	if err != nil {
		return false, fmt.Errorf("creating web apps client: %w", err)
	}

	authSettings, err := client.GetAuthSettingsV2(cfg.Context, rg, name, nil)
	if err != nil {
		return false, fmt.Errorf("getting auth settings for %s: %w", name, err)
	}

	if authSettings.Properties != nil &&
		authSettings.Properties.Platform != nil &&
		authSettings.Properties.Platform.Enabled != nil &&
		*authSettings.Properties.Platform.Enabled {
		return false, nil
	}

	return true, nil
}
