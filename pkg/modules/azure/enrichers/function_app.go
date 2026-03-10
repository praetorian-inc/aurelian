package enrichers

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v4"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("function_apps_public_http_triggers", enrichFunctionApp)
}

func enrichFunctionApp(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	functionAppName := result.ResourceName
	subscriptionID := result.SubscriptionID
	resourceGroupName := ParseResourceGroup(result.ResourceID)

	if functionAppName == "" || subscriptionID == "" || resourceGroupName == "" {
		return []plugin.AzureEnrichmentCommand{{
			Description:  "Enumerate Function App HTTP triggers",
			ActualOutput: "Error: Function App name, subscription ID, or resource group is missing",
			ExitCode:     1,
		}}, nil
	}

	webAppsClient, err := NewWebAppsClient(subscriptionID, cfg.Credential)
	if err != nil {
		return []plugin.AzureEnrichmentCommand{{
			Description:  "Enumerate Function App HTTP triggers via Management API",
			ActualOutput: fmt.Sprintf("Error creating WebApps client: %s", err.Error()),
			ExitCode:     1,
		}}, nil
	}

	// Step 0: Check IP restrictions via Management API
	ipRestrictionsCmd := checkIPRestrictionsCommand(cfg, webAppsClient, resourceGroupName, functionAppName, "Function App")

	// Step 1: Enumerate triggers from production slot
	cliEquiv := fmt.Sprintf("az functionapp function list --resource-group %s --name %s", resourceGroupName, functionAppName)
	triggers, totalFunctions, err := ListHTTPTriggers(cfg.Context, webAppsClient, resourceGroupName, functionAppName, "")
	if err != nil {
		return []plugin.AzureEnrichmentCommand{{
			Command:      cliEquiv,
			Description:  "Enumerate Function App HTTP triggers via Management API",
			ActualOutput: fmt.Sprintf("Error: %s", err.Error()),
			ExitCode:     1,
		}}, nil
	}

	// Step 2: Enumerate deployment slots and their triggers
	slotTriggers, slotCmd := funcAppEnumerateSlots(cfg, webAppsClient, resourceGroupName, functionAppName)
	var commands []plugin.AzureEnrichmentCommand

	// Merge slot triggers into main list
	triggers = append(triggers, slotTriggers...)

	// Build enumeration summary
	enumCmd := funcAppBuildEnumerationSummary(functionAppName, triggers, totalFunctions, cliEquiv)
	commands = append(commands, ipRestrictionsCmd, enumCmd)

	if slotCmd != nil {
		commands = append(commands, *slotCmd)
	}

	// Step 3: Probe anonymous HTTP triggers at their actual invoke URLs
	client := NewNoRedirectHTTPClient(10 * time.Second)

	for _, trigger := range triggers {
		if strings.EqualFold(trigger.AuthLevel, "anonymous") && trigger.InvokeURL != "" && !trigger.IsDisabled {
			probeCmd := funcAppProbeInvokeURL(client, trigger)
			commands = append(commands, probeCmd)
		}
	}

	// Step 4: SCM/Kudu probe
	scmCmd := probeSCMSite(client, functionAppName)
	commands = append(commands, scmCmd)

	// Step 5: EasyAuth cross-reference
	easyAuthCmd := checkEasyAuthCommand(cfg, webAppsClient, resourceGroupName, functionAppName)
	commands = append(commands, easyAuthCmd)

	return commands, nil
}

// funcAppEnumerateSlots discovers deployment slots and enumerates their HTTP triggers.
func funcAppEnumerateSlots(cfg plugin.AzureEnricherConfig, client *armappservice.WebAppsClient, resourceGroupName, functionAppName string) ([]HTTPTriggerInfo, *plugin.AzureEnrichmentCommand) {
	pager := client.NewListSlotsPager(resourceGroupName, functionAppName, nil)

	var slotNames []string
	for pager.More() {
		page, err := pager.NextPage(cfg.Context)
		if err != nil {
			cmd := plugin.AzureEnrichmentCommand{
				Command:      fmt.Sprintf("az functionapp deployment slot list --resource-group %s --name %s", resourceGroupName, functionAppName),
				Description:  "Enumerate deployment slots",
				ActualOutput: fmt.Sprintf("Error listing deployment slots: %s", err.Error()),
				ExitCode:     1,
			}
			return nil, &cmd
		}
		for _, slot := range page.Value {
			if slot.Name != nil {
				name := *slot.Name
				if idx := strings.LastIndex(name, "/"); idx >= 0 {
					name = name[idx+1:]
				}
				slotNames = append(slotNames, name)
			}
		}
	}

	if len(slotNames) == 0 {
		return nil, nil
	}

	var allSlotTriggers []HTTPTriggerInfo
	slotErrors := 0
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Deployment slots found: %d (%s)\n", len(slotNames), strings.Join(slotNames, ", ")))

	for _, slotName := range slotNames {
		triggers, totalFuncs, err := ListHTTPTriggers(cfg.Context, client, resourceGroupName, functionAppName, slotName)
		if err != nil {
			slotErrors++
			sb.WriteString(fmt.Sprintf("  Slot %s: error listing functions: %s\n", slotName, err.Error()))
			continue
		}
		sb.WriteString(fmt.Sprintf("  Slot %s: %d functions, %d HTTP triggers\n", slotName, totalFuncs, len(triggers)))
		allSlotTriggers = append(allSlotTriggers, triggers...)
	}

	exitCode := 0
	if slotErrors > 0 {
		sb.WriteString(fmt.Sprintf("\nWARNING: %d of %d slots failed enumeration — trigger data may be incomplete.", slotErrors, len(slotNames)))
		exitCode = -1
	}

	cmd := plugin.AzureEnrichmentCommand{
		Command:                   fmt.Sprintf("az functionapp deployment slot list --resource-group %s --name %s", resourceGroupName, functionAppName),
		Description:               "Enumerate deployment slot HTTP triggers",
		ExpectedOutputDescription: "Lists HTTP triggers in deployment slots (staging, canary, etc.)",
		ActualOutput:              sb.String(),
		ExitCode:                  exitCode,
	}

	return allSlotTriggers, &cmd
}

// funcAppBuildEnumerationSummary creates the summary command for trigger enumeration.
func funcAppBuildEnumerationSummary(functionAppName string, triggers []HTTPTriggerInfo, totalFunctions int, cliEquiv string) plugin.AzureEnrichmentCommand {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Function App: %s | Total functions: %d | HTTP triggers: %d\n\n", functionAppName, totalFunctions, len(triggers)))

	anonymousCount := 0
	for _, t := range triggers {
		status := "enabled"
		if t.IsDisabled {
			status = "DISABLED"
		}

		slotLabel := ""
		if t.SlotName != "" {
			slotLabel = fmt.Sprintf(" [slot:%s]", t.SlotName)
		}

		sb.WriteString(fmt.Sprintf("  %-30s | auth=%-10s | route=%-25s | %s%s\n", t.FunctionName, t.AuthLevel, t.Route, status, slotLabel))
		if t.InvokeURL != "" {
			sb.WriteString(fmt.Sprintf("  %-30s   invoke: %s\n", "", t.InvokeURL))
		}
		if strings.EqualFold(t.AuthLevel, "anonymous") {
			anonymousCount++
		}
	}

	if anonymousCount > 0 {
		sb.WriteString(fmt.Sprintf("\n%d anonymous HTTP trigger(s) found - no function key or auth token required", anonymousCount))
	}

	exitCode := 0
	if anonymousCount > 0 {
		exitCode = 1
	}

	return plugin.AzureEnrichmentCommand{
		Command:                   cliEquiv,
		Description:               "Enumerate Function App HTTP triggers via Management API",
		ExpectedOutputDescription: "Lists all HTTP triggers with auth levels, invoke URLs, and custom routes",
		ActualOutput:              sb.String(),
		ExitCode:                  exitCode,
	}
}

// funcAppProbeInvokeURL sends an HTTP GET to the actual invoke URL of an anonymous trigger.
func funcAppProbeInvokeURL(client *http.Client, trigger HTTPTriggerInfo) plugin.AzureEnrichmentCommand {
	slotLabel := ""
	if trigger.SlotName != "" {
		slotLabel = fmt.Sprintf(" [slot:%s]", trigger.SlotName)
	}

	cmd := plugin.AzureEnrichmentCommand{
		Command:                   fmt.Sprintf("curl -i --max-redirects 0 '%s' --max-time 10", trigger.InvokeURL),
		Description:               fmt.Sprintf("Probe anonymous trigger: %s (route: %s)%s", trigger.FunctionName, trigger.Route, slotLabel),
		ExpectedOutputDescription: "200 = anonymously accessible | 3xx = redirect (likely auth) | 401/403 = auth enforced | timeout = blocked",
	}

	resp, err := client.Get(trigger.InvokeURL)
	if err != nil {
		cmd.Error = err.Error()
		cmd.ActualOutput = fmt.Sprintf("Request failed: %s", err.Error())
		cmd.ExitCode = -1
		return cmd
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2000))

	var exitCode int
	var verdict string
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		exitCode = 1
		verdict = "ACCESSIBLE (anonymous)"
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		exitCode = 0
		location := resp.Header.Get("Location")
		verdict = fmt.Sprintf("REDIRECT to %s (likely auth gate)", location)
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		exitCode = 0
		verdict = "AUTH ENFORCED (despite anonymous config)"
	default:
		exitCode = 0
		verdict = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}

	cmd.ActualOutput = fmt.Sprintf("HTTP %d — %s\nBody preview: %s", resp.StatusCode, verdict, TruncateString(string(body), 800))
	cmd.ExitCode = exitCode

	return cmd
}

