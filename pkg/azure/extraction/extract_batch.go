package extraction

import (
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/batch/armbatch"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("microsoft.batch/batchaccounts", "batch-pool-starttasks", extractBatchPoolStartTasks)
}

func extractBatchPoolStartTasks(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, resourceGroup, segments, err := ParseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse batch account resource ID: %w", err)
	}
	accountName := segments["batchAccounts"]
	if accountName == "" {
		return fmt.Errorf("no batchAccounts segment in resource ID %s", r.ResourceID)
	}

	client, err := armbatch.NewPoolClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create batch pool client: %w", err)
	}

	pager := client.NewListByBatchAccountPager(resourceGroup, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx.Context)
		if err != nil {
			return handleExtractError(err, "batch-pool-starttasks", r.ResourceID)
		}
		for _, pool := range page.Value {
			if pool.Properties == nil || pool.Properties.StartTask == nil {
				continue
			}
			content, err := json.Marshal(pool.Properties.StartTask)
			if err != nil {
				continue
			}
			poolName := ""
			if pool.Name != nil {
				poolName = *pool.Name
			}
			label := fmt.Sprintf("Batch StartTask: %s", poolName)
			out.Send(output.ScanInputFromAzureResource(r, label, content))
		}
	}

	return nil
}
