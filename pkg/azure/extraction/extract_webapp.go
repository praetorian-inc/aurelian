package extraction

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

func init() {
	mustRegister("microsoft.web/sites", "webapp-settings", extractWebAppSettings)
	mustRegister("microsoft.web/sites", "webapp-connections", extractWebAppConnections)
	mustRegister("microsoft.web/sites", "webapp-hostkeys", extractWebAppHostKeys)
	mustRegister("microsoft.web/sites", "webapp-slots", extractWebAppSlots)
	mustRegister("microsoft.web/sites", "webapp-siteconfig", extractWebAppSiteConfig)
}

func extractWebAppSettings(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	resourceGroup, appName, err := parseWebAppID(r.ResourceID)
	if err != nil {
		return err
	}

	client, err := armappservice.NewWebAppsClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create web apps client: %w", err)
	}

	settings, err := client.ListApplicationSettings(ctx.Context, resourceGroup, appName, nil)
	if err != nil {
		return handleExtractError(err, "webapp-settings", r.ResourceID)
	}

	if len(settings.Properties) > 0 {
		if data, err := json.Marshal(settings.Properties); err == nil {
			out.Send(output.ScanInputFromAzureResource(r, "WebApp AppSettings", data))
		}
	}
	return nil
}

func extractWebAppConnections(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	resourceGroup, appName, err := parseWebAppID(r.ResourceID)
	if err != nil {
		return err
	}

	client, err := armappservice.NewWebAppsClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create web apps client: %w", err)
	}

	connStrings, err := client.ListConnectionStrings(ctx.Context, resourceGroup, appName, nil)
	if err != nil {
		return handleExtractError(err, "webapp-connections", r.ResourceID)
	}

	if connStrings.Properties != nil {
		if data, err := json.Marshal(connStrings.Properties); err == nil {
			out.Send(output.ScanInputFromAzureResource(r, "WebApp ConnectionStrings", data))
		}
	}
	return nil
}

func extractWebAppHostKeys(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	resourceGroup, appName, err := parseWebAppID(r.ResourceID)
	if err != nil {
		return err
	}

	client, err := armappservice.NewWebAppsClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create web apps client: %w", err)
	}

	hostKeys, err := client.ListHostKeys(ctx.Context, resourceGroup, appName, nil)
	if err != nil {
		return handleExtractError(err, "webapp-hostkeys", r.ResourceID)
	}

	if data, err := json.Marshal(hostKeys); err == nil && len(data) > 2 {
		out.Send(output.ScanInputFromAzureResource(r, "WebApp HostKeys", data))
	}
	return nil
}

func parseWebAppID(resourceID string) (resourceGroup, appName string, err error) {
	_, rg, segments, parseErr := parseAzureResourceID(resourceID)
	if parseErr != nil {
		return "", "", fmt.Errorf("failed to parse web app resource ID: %w", parseErr)
	}
	appName = segments["sites"]
	if appName == "" {
		return "", "", fmt.Errorf("no 'sites' segment in resource ID %s", resourceID)
	}
	return rg, appName, nil
}

func extractWebAppSlots(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	rg, appName, err := parseWebAppID(r.ResourceID)
	if err != nil {
		return err
	}

	client, err := armappservice.NewWebAppsClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create web apps client: %w", err)
	}

	pager := client.NewListSlotsPager(rg, appName, nil)
	paginator := ratelimit.NewAzurePaginator()
	err = paginator.Paginate(func() (bool, error) {
		page, err := pager.NextPage(ctx.Context)
		if err != nil {
			return true, err
		}
		for _, slot := range page.Value {
			if slot.Name == nil {
				continue
			}
			// Slot name is in format "appName/slotName"
			slotName := *slot.Name
			if idx := strings.Index(slotName, "/"); idx >= 0 {
				slotName = slotName[idx+1:]
			}

			// Extract slot app settings
			settings, settingsErr := client.ListApplicationSettingsSlot(ctx.Context, rg, appName, slotName, nil)
			if settingsErr != nil {
				if herr := handleExtractError(settingsErr, "webapp-slots", r.ResourceID); herr != nil {
					slog.Warn("failed to list slot app settings", "slot", slotName, "error", herr)
				}
			} else if len(settings.Properties) > 0 {
				if data, merr := json.Marshal(settings.Properties); merr == nil {
					label := fmt.Sprintf("WebApp Slot:%s:AppSettings", slotName)
					out.Send(output.ScanInputFromAzureResource(r, label, data))
				}
			}

			// Extract slot connection strings
			connStrings, connErr := client.ListConnectionStringsSlot(ctx.Context, rg, appName, slotName, nil)
			if connErr != nil {
				if herr := handleExtractError(connErr, "webapp-slots", r.ResourceID); herr != nil {
					slog.Warn("failed to list slot connection strings", "slot", slotName, "error", herr)
				}
			} else if connStrings.Properties != nil {
				if data, merr := json.Marshal(connStrings.Properties); merr == nil {
					label := fmt.Sprintf("WebApp Slot:%s:ConnectionStrings", slotName)
					out.Send(output.ScanInputFromAzureResource(r, label, data))
				}
			}
		}
		return pager.More(), nil
	})
	return handleExtractError(err, "webapp-slots", r.ResourceID)
}

func extractWebAppSiteConfig(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	rg, appName, err := parseWebAppID(r.ResourceID)
	if err != nil {
		return err
	}

	client, err := armappservice.NewWebAppsClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create web apps client: %w", err)
	}

	config, err := client.GetConfiguration(ctx.Context, rg, appName, nil)
	if err != nil {
		return handleExtractError(err, "webapp-siteconfig", r.ResourceID)
	}

	if config.Properties != nil {
		if data, merr := json.Marshal(config.Properties); merr == nil {
			out.Send(output.ScanInputFromAzureResource(r, "WebApp SiteConfig", data))
		}
	}
	return nil
}
