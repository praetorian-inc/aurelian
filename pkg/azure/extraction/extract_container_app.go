package extraction

import (
	"encoding/json"
	"fmt"
	"log/slog"

	armappcontainers "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appcontainers/armappcontainers/v3"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("microsoft.app/containerapps", "container-app-envvars", extractContainerAppEnvVars)
}

func extractContainerAppEnvVars(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, resourceGroup, segments, err := parseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse resource ID: %w", err)
	}
	name := segments["containerApps"]
	if name == "" {
		return fmt.Errorf("no containerApps segment in resource ID %s", r.ResourceID)
	}

	client, err := armappcontainers.NewContainerAppsClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create container apps client: %w", err)
	}

	result, err := client.Get(ctx.Context, resourceGroup, name, nil)
	if err != nil {
		return handleExtractError(err, "container-app-envvars", r.ResourceID)
	}

	if result.Properties == nil || result.Properties.Template == nil || result.Properties.Template.Containers == nil {
		return nil
	}

	for _, container := range result.Properties.Template.Containers {
		if container.Env == nil {
			continue
		}

		containerName := ""
		if container.Name != nil {
			containerName = *container.Name
		}

		envVars := make(map[string]string)
		for _, ev := range container.Env {
			if ev.Name == nil || ev.Value == nil {
				// Skip secretRef entries (Value is nil when referencing a secret)
				continue
			}
			envVars[*ev.Name] = *ev.Value
		}

		if len(envVars) == 0 {
			continue
		}

		content, err := json.Marshal(envVars)
		if err != nil {
			slog.Warn("failed to marshal container app env vars", "container", containerName, "error", err)
			continue
		}
		label := fmt.Sprintf("ContainerApp EnvVars: %s", containerName)
		out.Send(output.ScanInputFromAzureResource(r, label, content))
	}

	return nil
}
