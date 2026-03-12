package extraction

import (
	"encoding/json"
	"fmt"

	armlogic "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/logic/armlogic"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("microsoft.logic/workflows", "logic-app-definition", extractLogicAppDefinition)
}

func extractLogicAppDefinition(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	rg, workflowName, err := parseLogicAppID(r.ResourceID)
	if err != nil {
		return err
	}

	client, err := armlogic.NewWorkflowsClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create logic workflows client: %w", err)
	}

	resp, err := client.Get(ctx.Context, rg, workflowName, nil)
	if err != nil {
		return handleExtractError(err, "logic-app-definition", r.ResourceID)
	}

	if resp.Properties != nil && resp.Properties.Definition != nil {
		if data, merr := json.Marshal(resp.Properties.Definition); merr == nil {
			out.Send(output.ScanInputFromAzureResource(r, "LogicApp Definition", data))
		}
	}

	if resp.Properties != nil && resp.Properties.Parameters != nil {
		if data, merr := json.Marshal(resp.Properties.Parameters); merr == nil {
			out.Send(output.ScanInputFromAzureResource(r, "LogicApp Parameters", data))
		}
	}

	return nil
}

func parseLogicAppID(resourceID string) (resourceGroup, workflowName string, err error) {
	_, rg, segments, parseErr := ParseAzureResourceID(resourceID)
	if parseErr != nil {
		return "", "", fmt.Errorf("failed to parse logic app resource ID: %w", parseErr)
	}
	workflowName = segments["workflows"]
	if workflowName == "" {
		return "", "", fmt.Errorf("no 'workflows' segment in resource ID %s", resourceID)
	}
	return rg, workflowName, nil
}
