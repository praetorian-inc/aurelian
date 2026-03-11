package extraction

import (
	"encoding/json"
	"fmt"
	"log/slog"

	armhybridcompute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/hybridcompute/armhybridcompute/v2"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("microsoft.hybridcompute/machines", "arc-extensions", extractArcExtensions)
}

func extractArcExtensions(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, resourceGroup, segments, err := parseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse resource ID: %w", err)
	}
	name := segments["machines"]
	if name == "" {
		return fmt.Errorf("no machines segment in resource ID %s", r.ResourceID)
	}

	client, err := armhybridcompute.NewMachineExtensionsClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create Arc machine extensions client: %w", err)
	}

	pager := client.NewListPager(resourceGroup, name, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx.Context)
		if err != nil {
			return handleExtractError(err, "arc-extensions", r.ResourceID)
		}
		for _, ext := range page.Value {
			if ext.Properties == nil {
				continue
			}
			content, err := json.Marshal(ext.Properties)
			if err != nil {
				slog.Warn("failed to marshal Arc extension properties", "machine", name, "error", err)
				continue
			}
			extName := ""
			if ext.Name != nil {
				extName = *ext.Name
			}
			label := fmt.Sprintf("Arc Extension: %s", extName)
			out.Send(output.ScanInputFromAzureResource(r, label, content))
		}
	}

	return nil
}
