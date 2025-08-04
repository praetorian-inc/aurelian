package azure

import (
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	jtypes "github.com/praetorian-inc/janus-framework/pkg/types"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// AzureWebAppSecretsLink extracts secrets from Azure Web Apps
type AzureWebAppSecretsLink struct {
	*chain.Base
}

func NewAzureWebAppSecretsLink(configs ...cfg.Config) chain.Link {
	l := &AzureWebAppSecretsLink{}
	l.Base = chain.NewBase(l, configs...)
	return l
}

func (l *AzureWebAppSecretsLink) Params() []cfg.Param {
	return []cfg.Param{
		options.AzureSubscription(),
	}
}

func (l *AzureWebAppSecretsLink) Process(resource *model.AzureResource) error {
	subscriptionID := resource.AccountRef

	// Extract resource group and web app name from resource ID
	resourceGroup, appName, err := l.parseWebAppResourceID(resource.Key)
	if err != nil {
		return fmt.Errorf("failed to parse web app resource ID: %w", err)
	}

	// Get Azure credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("failed to get Azure credentials: %w", err)
	}

	// Create web apps client
	client, err := armappservice.NewWebAppsClient(subscriptionID, cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create web apps client: %w", err)
	}

	// Get application settings
	l.Logger.Debug("Getting web app application settings",
		"resource_group", resourceGroup,
		"app_name", appName)

	settings, err := client.ListApplicationSettings(l.Context(), resourceGroup, appName, nil)
	if err != nil {
		l.Logger.Error("Failed to get application settings", "error", err.Error())
	} else if settings.Properties != nil {
		// Convert settings to JSON for scanning
		settingsContent, err := json.Marshal(settings.Properties)
		if err == nil {
			npInput := jtypes.NPInput{
				Content: string(settingsContent),
				Provenance: jtypes.NPProvenance{
					Platform:     "azure",
					ResourceType: "Microsoft.Web/sites/settings",
					ResourceID:   fmt.Sprintf("%s/config/appsettings", resource.Key),
					AccountID:    subscriptionID,
				},
			}
			l.Send(npInput)
		}
	}

	// Get connection strings
	l.Logger.Debug("Getting web app connection strings",
		"resource_group", resourceGroup,
		"app_name", appName)

	connStrings, err := client.ListConnectionStrings(l.Context(), resourceGroup, appName, nil)
	if err != nil {
		l.Logger.Error("Failed to get connection strings", "error", err.Error())
	} else if connStrings.Properties != nil {
		// Convert connection strings to JSON for scanning
		connContent, err := json.Marshal(connStrings.Properties)
		if err == nil {
			npInput := jtypes.NPInput{
				Content: string(connContent),
				Provenance: jtypes.NPProvenance{
					Platform:     "azure",
					ResourceType: "Microsoft.Web/sites/connectionStrings",
					ResourceID:   fmt.Sprintf("%s/config/connectionstrings", resource.Key),
					AccountID:    subscriptionID,
				},
			}
			l.Send(npInput)
		}
	}

	// Get site configuration
	l.Logger.Debug("Getting web app site configuration",
		"resource_group", resourceGroup,
		"app_name", appName)

	config, err := client.GetConfiguration(l.Context(), resourceGroup, appName, nil)
	if err != nil {
		l.Logger.Error("Failed to get site configuration", "error", err.Error())
	} else if config.Properties != nil {
		// Convert configuration to JSON for scanning
		configContent, err := json.Marshal(config.Properties)
		if err == nil {
			npInput := jtypes.NPInput{
				Content: string(configContent),
				Provenance: jtypes.NPProvenance{
					Platform:     "azure",
					ResourceType: "Microsoft.Web/sites/configuration",
					ResourceID:   fmt.Sprintf("%s/config/web", resource.Key),
					AccountID:    subscriptionID,
				},
			}
			l.Send(npInput)
		}
	}

	// Get function keys if this is a function app
	if l.isFunctionApp(resource) {
		l.Logger.Debug("Getting function app keys",
			"resource_group", resourceGroup,
			"app_name", appName)

		keys, err := client.ListHostKeys(l.Context(), resourceGroup, appName, nil)
		if err != nil {
			l.Logger.Error("Failed to get function keys", "error", err.Error())
		} else {
			// Convert keys to JSON for scanning
			keysContent, err := json.Marshal(keys)
			if err == nil {
				npInput := jtypes.NPInput{
					Content: string(keysContent),
					Provenance: jtypes.NPProvenance{
						Platform:     "azure",
						ResourceType: "Microsoft.Web/sites/keys",
						ResourceID:   fmt.Sprintf("%s/host/default/keys", resource.Key),
						AccountID:    subscriptionID,
					},
				}
				l.Send(npInput)
			}
		}
	}

	return nil
}

func (l *AzureWebAppSecretsLink) parseWebAppResourceID(resourceID string) (resourceGroup, appName string, err error) {
	parsed, err := helpers.ParseAzureResourceID(resourceID)
	if err != nil {
		return "", "", err
	}

	resourceGroup = parsed["resourceGroups"]
	appName = parsed["sites"]

	if resourceGroup == "" || appName == "" {
		return "", "", fmt.Errorf("invalid web app resource ID format")
	}

	return resourceGroup, appName, nil
}

func (l *AzureWebAppSecretsLink) isFunctionApp(resource *model.AzureResource) bool {
	// Check if this is a function app by examining properties
	if resource.Properties != nil {
		if kind, ok := resource.Properties["kind"].(string); ok {
			return kind == "functionapp" || kind == "functionapp,linux"
		}
	}
	return false
}
