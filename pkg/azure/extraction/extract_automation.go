package extraction

import (
	"encoding/json"
	"fmt"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
	"io"
	"log/slog"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/automation/armautomation"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("microsoft.automation/automationaccounts", "automation-variables", extractAutomationVariables)
	mustRegister("microsoft.automation/automationaccounts", "automation-runbooks", extractAutomationRunbooks)
}

func extractAutomationVariables(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, resourceGroup, segments, err := parseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse automation account resource ID: %w", err)
	}
	accountName := segments["automationAccounts"]
	if accountName == "" {
		return fmt.Errorf("no automationAccounts segment in resource ID %s", r.ResourceID)
	}

	client, err := armautomation.NewVariableClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create automation variable client: %w", err)
	}

	pager := client.NewListByAutomationAccountPager(resourceGroup, accountName, nil)
	paginator := ratelimit.NewAzurePaginator()
	return paginator.Paginate(func() (bool, error) {
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
}

func extractAutomationRunbooks(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, resourceGroup, segments, err := parseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse automation account resource ID: %w", err)
	}
	accountName := segments["automationAccounts"]
	if accountName == "" {
		return fmt.Errorf("no automationAccounts segment in resource ID %s", r.ResourceID)
	}

	client, err := armautomation.NewRunbookClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create automation runbook client: %w", err)
	}

	pager := client.NewListByAutomationAccountPager(resourceGroup, accountName, nil)
	paginator := ratelimit.NewAzurePaginator()
	return paginator.Paginate(func() (bool, error) {
		page, err := pager.NextPage(ctx.Context)
		if err != nil {
			return true, err
		}
		for _, rb := range page.Value {
			if rb.Name == nil {
				continue
			}
			content, err := fetchRunbookContent(ctx, r.SubscriptionID, resourceGroup, accountName, *rb.Name)
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
}

// fetchRunbookContent retrieves the actual content of a runbook via the REST API.
// The SDK's RunbookClient doesn't expose content directly — we use the
// GET .../runbooks/{name}/content endpoint.
func fetchRunbookContent(ctx extractContext, subscriptionID, resourceGroup, accountName, runbookName string) ([]byte, error) {
	url := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Automation/automationAccounts/%s/runbooks/%s/content?api-version=2023-11-01",
		subscriptionID, resourceGroup, accountName, runbookName,
	)

	token, err := ctx.Cred.GetToken(ctx.Context, policy.TokenRequestOptions{
		Scopes: []string{"https://management.azure.com/.default"},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx.Context, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("runbook content request returned %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}
