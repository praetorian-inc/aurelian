package extraction

import (
	"encoding/json"
	"fmt"

	armsynapse "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/synapse/armsynapse"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("microsoft.synapse/workspaces", "synapse-properties", extractSynapseProperties)
}

// extractSynapseProperties retrieves the ARM-level properties of a Synapse workspace,
// including connectivity endpoints.
// TODO: Implement data-plane linked services extraction via REST API:
// GET https://{workspaceName}.dev.azuresynapse.net/linkedservices?api-version=2020-12-01
// The armsynapse SDK does not expose a LinkedServicesClient; data-plane access would require
// using azcore pipeline or net/http with BearerTokenPolicy for auth against the dev endpoint.
func extractSynapseProperties(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, resourceGroup, segments, err := ParseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse Synapse workspace resource ID: %w", err)
	}

	workspaceName := segments["workspaces"]
	if workspaceName == "" {
		return fmt.Errorf("no workspaces segment in resource ID %s", r.ResourceID)
	}

	wsClient, err := armsynapse.NewWorkspacesClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create Synapse workspaces client: %w", err)
	}

	result, err := wsClient.Get(ctx.Context, resourceGroup, workspaceName, nil)
	if err != nil {
		return handleExtractError(err, "synapse-properties", r.ResourceID)
	}

	if result.Properties == nil {
		return nil
	}

	content, err := json.Marshal(result.Properties)
	if err != nil {
		return fmt.Errorf("failed to marshal Synapse workspace properties: %w", err)
	}

	label := fmt.Sprintf("Synapse Properties: %s", workspaceName)
	out.Send(output.ScanInputFromAzureResource(r, label, content))

	return nil
}
