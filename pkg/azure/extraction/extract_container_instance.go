package extraction

import (
	"encoding/json"
	"fmt"
	"log/slog"

	armcontainerinstance "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerinstance/armcontainerinstance/v2"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("microsoft.containerinstance/containergroups", "container-instance-envvars", extractContainerInstanceEnvVars)
}

func extractContainerInstanceEnvVars(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, resourceGroup, segments, err := ParseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse resource ID: %w", err)
	}
	name := segments["containerGroups"]
	if name == "" {
		return fmt.Errorf("no containerGroups segment in resource ID %s", r.ResourceID)
	}

	client, err := armcontainerinstance.NewContainerGroupsClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create container groups client: %w", err)
	}

	result, err := client.Get(ctx.Context, resourceGroup, name, nil)
	if err != nil {
		return handleExtractError(err, "container-instance-envvars", r.ResourceID)
	}

	if result.Properties == nil || result.Properties.Containers == nil {
		return nil
	}

	for _, container := range result.Properties.Containers {
		if container.Properties == nil || container.Properties.EnvironmentVariables == nil {
			continue
		}

		containerName := ""
		if container.Name != nil {
			containerName = *container.Name
		}

		envVars := make(map[string]string)
		for _, ev := range container.Properties.EnvironmentVariables {
			if ev.Name == nil || ev.Value == nil {
				continue
			}
			envVars[*ev.Name] = *ev.Value
		}

		if len(envVars) == 0 {
			continue
		}

		content, err := json.Marshal(envVars)
		if err != nil {
			slog.Warn("failed to marshal container instance env vars", "container", containerName, "error", err)
			continue
		}
		label := fmt.Sprintf("ContainerInstance EnvVars: %s", containerName)
		out.Send(output.ScanInputFromAzureResource(r, label, content))
	}

	return nil
}
