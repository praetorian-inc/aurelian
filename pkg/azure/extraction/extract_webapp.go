package extraction

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("Microsoft.Web/sites", "webapp-appsettings", extractWebAppSettings)
	mustRegister("Microsoft.Web/sites", "webapp-connstrings", extractWebAppConnectionStrings)
	mustRegister("Microsoft.Web/sites", "webapp-hostkeys", extractWebAppHostKeys)
}

func parseWebAppResourceID(resourceID string) (resourceGroup, appName string, err error) {
	rg, name, err := parseResourceID(resourceID, "resourceGroups", "sites")
	if err != nil {
		return "", "", fmt.Errorf("invalid web app resource ID %q: %w", resourceID, err)
	}
	return rg, name, nil
}

func extractWebAppSettings(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	rg, appName, err := parseWebAppResourceID(r.ResourceID)
	if err != nil {
		return err
	}

	client, err := armappservice.NewWebAppsClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create web apps client: %w", err)
	}

	settings, err := client.ListApplicationSettings(ctx.Context, rg, appName, nil)
	if err != nil {
		slog.Warn("failed to list app settings", "app", appName, "error", err)
		return nil
	}

	if len(settings.Properties) == 0 {
		return nil
	}

	data, err := json.Marshal(settings.Properties)
	if err != nil {
		return nil
	}
	out.Send(output.ScanInputFromAzureResource(r, "AppSettings", data))

	return nil
}

func extractWebAppConnectionStrings(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	rg, appName, err := parseWebAppResourceID(r.ResourceID)
	if err != nil {
		return err
	}

	client, err := armappservice.NewWebAppsClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create web apps client: %w", err)
	}

	connStrings, err := client.ListConnectionStrings(ctx.Context, rg, appName, nil)
	if err != nil {
		slog.Warn("failed to list connection strings", "app", appName, "error", err)
		return nil
	}

	if connStrings.Properties == nil {
		return nil
	}

	data, err := json.Marshal(connStrings.Properties)
	if err != nil {
		return nil
	}
	out.Send(output.ScanInputFromAzureResource(r, "ConnectionStrings", data))

	return nil
}

func extractWebAppHostKeys(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	rg, appName, err := parseWebAppResourceID(r.ResourceID)
	if err != nil {
		return err
	}

	client, err := armappservice.NewWebAppsClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create web apps client: %w", err)
	}

	hostKeys, err := client.ListHostKeys(ctx.Context, rg, appName, nil)
	if err != nil {
		slog.Warn("failed to list host keys", "app", appName, "error", err)
		return nil
	}

	data, err := json.Marshal(hostKeys)
	if err != nil {
		return nil
	}

	hasContent := len(data) > 2
	if !hasContent {
		return nil
	}

	out.Send(output.ScanInputFromAzureResource(r, "HostKeys", data))
	return nil
}
