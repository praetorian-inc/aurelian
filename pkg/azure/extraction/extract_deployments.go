package extraction

import (
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("microsoft.resources/deployments", "deployment-params", extractDeploymentParams)
}

func extractDeploymentParams(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, resourceGroup, segments, err := ParseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse deployment resource ID: %w", err)
	}
	deploymentName := segments["deployments"]
	if deploymentName == "" {
		return fmt.Errorf("no deployments segment in resource ID %s", r.ResourceID)
	}

	client, err := armresources.NewDeploymentsClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create deployments client: %w", err)
	}

	result, err := client.Get(ctx.Context, resourceGroup, deploymentName, nil)
	if err != nil {
		return handleExtractError(err, "deployment-params", r.ResourceID)
	}

	if result.Properties == nil {
		return nil
	}

	// Extract Parameters
	if result.Properties.Parameters != nil {
		content, err := json.Marshal(result.Properties.Parameters)
		if err == nil && len(content) > 2 {
			out.Send(output.ScanInputFromAzureResource(r, "ARM Deployment Parameters", content))
		}
	}

	// Extract Outputs
	if result.Properties.Outputs != nil {
		content, err := json.Marshal(result.Properties.Outputs)
		if err == nil && len(content) > 2 {
			out.Send(output.ScanInputFromAzureResource(r, "ARM Deployment Outputs", content))
		}
	}

	return nil
}
