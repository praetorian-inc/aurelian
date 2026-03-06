package extraction

import (
	"encoding/json"
	"fmt"
	"log/slog"

	armdatafactory "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory/v8"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("microsoft.datafactory/factories", "adf-pipelines", extractADFPipelines)
	mustRegister("microsoft.datafactory/factories", "adf-linkedservices", extractADFLinkedServices)
}

func extractADFPipelines(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, resourceGroup, segments, err := parseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse Data Factory resource ID: %w", err)
	}

	factoryName := segments["factories"]
	if factoryName == "" {
		return fmt.Errorf("no factories segment in resource ID %s", r.ResourceID)
	}

	client, err := armdatafactory.NewPipelinesClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create ADF pipelines client: %w", err)
	}

	pager := client.NewListByFactoryPager(resourceGroup, factoryName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx.Context)
		if err != nil {
			return handleExtractError(err, "adf-pipelines", r.ResourceID)
		}

		for _, pipeline := range page.Value {
			if pipeline.Properties == nil {
				continue
			}

			content, err := json.Marshal(pipeline.Properties)
			if err != nil {
				slog.Warn("failed to marshal ADF pipeline properties", "factory", factoryName, "error", err)
				continue
			}

			pipelineName := ""
			if pipeline.Name != nil {
				pipelineName = *pipeline.Name
			}
			label := fmt.Sprintf("ADF Pipeline: %s", pipelineName)
			out.Send(output.ScanInputFromAzureResource(r, label, content))
		}
	}

	return nil
}

func extractADFLinkedServices(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, resourceGroup, segments, err := parseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse Data Factory resource ID: %w", err)
	}

	factoryName := segments["factories"]
	if factoryName == "" {
		return fmt.Errorf("no factories segment in resource ID %s", r.ResourceID)
	}

	client, err := armdatafactory.NewLinkedServicesClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create ADF linked services client: %w", err)
	}

	pager := client.NewListByFactoryPager(resourceGroup, factoryName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx.Context)
		if err != nil {
			return handleExtractError(err, "adf-linkedservices", r.ResourceID)
		}

		for _, svc := range page.Value {
			if svc.Properties == nil {
				continue
			}

			content, err := json.Marshal(svc.Properties)
			if err != nil {
				slog.Warn("failed to marshal ADF linked service properties", "factory", factoryName, "error", err)
				continue
			}

			serviceName := ""
			if svc.Name != nil {
				serviceName = *svc.Name
			}
			label := fmt.Sprintf("ADF LinkedService: %s", serviceName)
			out.Send(output.ScanInputFromAzureResource(r, label, content))
		}
	}

	return nil
}
