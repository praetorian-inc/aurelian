package extraction

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/automation/armautomation"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("Microsoft.Automation/automationAccounts", "automation-variables", extractAutomationVariables)
	mustRegister("Microsoft.Automation/automationAccounts", "automation-runbooks", extractAutomationRunbooks)
}

func parseAutomationAccountResourceID(resourceID string) (resourceGroup, accountName string, err error) {
	rg, name, err := parseResourceID(resourceID, "resourceGroups", "automationAccounts")
	if err != nil {
		return "", "", fmt.Errorf("invalid automation account resource ID %q: %w", resourceID, err)
	}
	return rg, name, nil
}

func extractAutomationVariables(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	rg, acctName, err := parseAutomationAccountResourceID(r.ResourceID)
	if err != nil {
		return err
	}

	client, err := armautomation.NewVariableClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create automation variable client: %w", err)
	}

	pager := client.NewListByAutomationAccountPager(rg, acctName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx.Context)
		if err != nil {
			slog.Warn("failed to list automation variables", "account", acctName, "error", err)
			return nil
		}
		for _, v := range page.Value {
			if v == nil || v.Properties == nil {
				continue
			}
			data, err := json.Marshal(v.Properties)
			if err != nil {
				continue
			}
			varName := ""
			if v.Name != nil {
				varName = *v.Name
			}
			label := fmt.Sprintf("Variable:%s", varName)
			out.Send(output.ScanInputFromAzureResource(r, label, data))
		}
	}

	return nil
}

func extractAutomationRunbooks(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	rg, acctName, err := parseAutomationAccountResourceID(r.ResourceID)
	if err != nil {
		return err
	}

	client, err := armautomation.NewRunbookClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create automation runbook client: %w", err)
	}

	pager := client.NewListByAutomationAccountPager(rg, acctName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx.Context)
		if err != nil {
			slog.Warn("failed to list automation runbooks", "account", acctName, "error", err)
			return nil
		}
		for _, rb := range page.Value {
			if rb == nil || rb.Properties == nil {
				continue
			}
			data, err := json.Marshal(rb.Properties)
			if err != nil {
				continue
			}
			rbName := ""
			if rb.Name != nil {
				rbName = *rb.Name
			}
			label := fmt.Sprintf("Runbook:%s", rbName)
			out.Send(output.ScanInputFromAzureResource(r, label, data))
		}
	}

	return nil
}
