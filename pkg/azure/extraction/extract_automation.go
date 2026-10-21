package extraction

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/automation/armautomation"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

func init() {
	mustRegister("microsoft.automation/automationaccounts", "automation-variables", extractAutomationVariables)
	mustRegister("microsoft.automation/automationaccounts", "automation-runbooks", extractAutomationRunbooks)
}

func extractAutomationVariables(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, resourceGroup, segments, err := ParseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse automation account resource ID: %w", err)
	}
	accountName := segments["automationAccounts"]
	if accountName == "" {
		return fmt.Errorf("no automationAccounts segment in resource ID %s", r.ResourceID)
	}

	options := ctx.Env.ARMClientOptions()
	options.APIVersion = "2020-01-13-preview" // Preserve the pre-upgrade API version.
	client, err := armautomation.NewVariableClient(r.SubscriptionID, ctx.Cred, options)
	if err != nil {
		return fmt.Errorf("failed to create automation variable client: %w", err)
	}

	pager := client.NewListByAutomationAccountPager(resourceGroup, accountName, nil)
	paginator := ratelimit.NewAzurePaginator()
	err = paginator.Paginate(func() (bool, error) {
		page, err := pager.NextPage(ctx.Context)
		if err != nil {
			return true, err
		}
		for _, v := range page.Value {
			if v.Properties == nil || v.Properties.Value == nil {
				continue
			}
			varName := ""
			if v.Name != nil {
				varName = *v.Name
			}
			content, _ := json.Marshal(map[string]string{
				"name":  varName,
				"value": *v.Properties.Value,
			})
			label := fmt.Sprintf("Automation Variable: %s", varName)
			out.Send(output.ScanInputFromAzureResource(r, label, content))
		}
		return pager.More(), nil
	})
	return handleExtractError(err, "automation-variables", r.ResourceID)
}

func extractAutomationRunbooks(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, resourceGroup, segments, err := ParseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse automation account resource ID: %w", err)
	}
	accountName := segments["automationAccounts"]
	if accountName == "" {
		return fmt.Errorf("no automationAccounts segment in resource ID %s", r.ResourceID)
	}

	options := ctx.Env.ARMClientOptions()
	options.APIVersion = "2018-06-30" // Preserve the pre-upgrade list API version.
	client, err := armautomation.NewRunbookClient(r.SubscriptionID, ctx.Cred, options)
	if err != nil {
		return fmt.Errorf("failed to create automation runbook client: %w", err)
	}

	contentOptions := ctx.Env.ARMClientOptions()
	contentOptions.APIVersion = "2023-11-01"
	contentOptions.DisableRPRegistration = true
	contentOptions.Retry.MaxRetries = -1
	contentClient, err := armautomation.NewRunbookClient(r.SubscriptionID, ctx.Cred, contentOptions)
	if err != nil {
		return fmt.Errorf("failed to create runbook content client: %w", err)
	}

	pager := client.NewListByAutomationAccountPager(resourceGroup, accountName, nil)
	paginator := ratelimit.NewAzurePaginator()
	err = paginator.Paginate(func() (bool, error) {
		page, err := pager.NextPage(ctx.Context)
		if err != nil {
			return true, err
		}
		for _, rb := range page.Value {
			if rb.Name == nil {
				continue
			}
			content, err := fetchRunbookContent(ctx.Context, contentClient, resourceGroup, accountName, *rb.Name)
			if err != nil {
				slog.Warn("failed to fetch runbook content", "runbook", *rb.Name, "error", err)
				continue
			}
			if len(content) == 0 {
				continue
			}
			label := fmt.Sprintf("Automation Runbook: %s", *rb.Name)
			out.Send(output.ScanInputFromAzureResource(r, label, content))
		}
		return pager.More(), nil
	})
	return handleExtractError(err, "automation-runbooks", r.ResourceID)
}

func fetchRunbookContent(ctx context.Context, client *armautomation.RunbookClient, resourceGroup, accountName, runbookName string) ([]byte, error) {
	resp, err := client.GetContent(ctx, resourceGroup, accountName, runbookName, nil)
	if err != nil {
		return nil, err
	}
	return []byte(*resp.Value), nil
}
