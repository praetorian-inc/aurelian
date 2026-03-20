package extraction

import (
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("microsoft.containerregistry/registries", "acr-tasks", extractACRTasks)
}

func extractACRTasks(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, resourceGroup, segments, err := ParseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse ACR resource ID: %w", err)
	}
	registryName := segments["registries"]
	if registryName == "" {
		return fmt.Errorf("no registries segment in resource ID %s", r.ResourceID)
	}

	client, err := armcontainerregistry.NewTasksClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create ACR tasks client: %w", err)
	}

	pager := client.NewListPager(resourceGroup, registryName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx.Context)
		if err != nil {
			return handleExtractError(err, "acr-tasks", r.ResourceID)
		}
		for _, task := range page.Value {
			if task.Properties == nil {
				continue
			}
			content, err := json.Marshal(task.Properties)
			if err != nil {
				continue
			}
			taskName := ""
			if task.Name != nil {
				taskName = *task.Name
			}
			label := fmt.Sprintf("ACR Task: %s", taskName)
			out.Send(output.ScanInputFromAzureResource(r, label, content))
		}
	}

	return nil
}
