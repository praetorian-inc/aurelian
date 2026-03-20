package extraction

import (
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// extractDiagnosticSettings reads diagnostic settings for any resource.
// Opt-in: only called when DiagnosticsEnabled is true in extractContext.
// This is NOT registered per-type — it will be called from the dispatcher.
func extractDiagnosticSettings(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	client, err := armmonitor.NewDiagnosticSettingsClient(ctx.Cred, nil)
	if err != nil {
		return handleExtractError(err, "diagnostic-settings", r.ResourceID)
	}

	pager := client.NewListPager(r.ResourceID, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx.Context)
		if err != nil {
			return handleExtractError(err, "diagnostic-settings", r.ResourceID)
		}
		for _, ds := range page.Value {
			if ds.Properties == nil {
				continue
			}
			content, err := json.Marshal(ds.Properties)
			if err != nil {
				continue
			}
			label := "DiagnosticSettings"
			if ds.Name != nil {
				label = fmt.Sprintf("DiagnosticSettings: %s", *ds.Name)
			}
			out.Send(output.ScanInputFromAzureResource(r, label, content))
		}
	}

	return nil
}
