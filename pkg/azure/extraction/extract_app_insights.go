package extraction

import (
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/applicationinsights/armapplicationinsights"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("microsoft.insights/components", "app-insights-keys", extractAppInsightsKeys)
}

func extractAppInsightsKeys(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, resourceGroup, segments, err := parseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse App Insights resource ID: %w", err)
	}
	componentName := segments["components"]
	if componentName == "" {
		return fmt.Errorf("no components segment in resource ID %s", r.ResourceID)
	}

	client, err := armapplicationinsights.NewComponentsClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create App Insights client: %w", err)
	}

	result, err := client.Get(ctx.Context, resourceGroup, componentName, nil)
	if err != nil {
		return handleExtractError(err, "app-insights-keys", r.ResourceID)
	}

	if result.Properties == nil {
		return nil
	}

	keys := map[string]string{}
	if result.Properties.InstrumentationKey != nil {
		keys["InstrumentationKey"] = *result.Properties.InstrumentationKey
	}
	if result.Properties.ConnectionString != nil {
		keys["ConnectionString"] = *result.Properties.ConnectionString
	}

	if len(keys) == 0 {
		return nil
	}

	content, err := json.Marshal(keys)
	if err != nil {
		return fmt.Errorf("failed to marshal App Insights keys: %w", err)
	}

	out.Send(output.ScanInputFromAzureResource(r, "AppInsights Keys", content))
	return nil
}
