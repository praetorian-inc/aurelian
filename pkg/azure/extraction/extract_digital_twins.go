package extraction

import (
	"encoding/json"
	"fmt"

	armdigitaltwins "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/digitaltwins/armdigitaltwins"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("microsoft.digitaltwins/digitaltwinsinstances", "digitaltwins-properties", extractDigitalTwinsProperties)
}

// extractDigitalTwinsProperties retrieves the ARM-level properties of a Digital Twins instance.
// TODO: Implement data-plane twin query via REST API (POST {endpoint}/query?api-version=2022-05-31)
// to enumerate digital twins with SELECT * FROM digitaltwins. The Go SDK does not have a
// data-plane client for Digital Twins; this would require using azcore pipeline or net/http
// with BearerTokenPolicy for auth.
func extractDigitalTwinsProperties(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, resourceGroup, segments, err := ParseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse Digital Twins resource ID: %w", err)
	}

	instanceName := segments["digitalTwinsInstances"]
	if instanceName == "" {
		return fmt.Errorf("no digitalTwinsInstances segment in resource ID %s", r.ResourceID)
	}

	armClient, err := armdigitaltwins.NewClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create Digital Twins ARM client: %w", err)
	}

	result, err := armClient.Get(ctx.Context, resourceGroup, instanceName, nil)
	if err != nil {
		return handleExtractError(err, "digitaltwins-properties", r.ResourceID)
	}

	if result.Properties == nil {
		return nil
	}

	content, err := json.Marshal(result.Properties)
	if err != nil {
		return fmt.Errorf("failed to marshal Digital Twins properties: %w", err)
	}

	label := fmt.Sprintf("DigitalTwins Properties: %s", instanceName)
	out.Send(output.ScanInputFromAzureResource(r, label, content))

	return nil
}
