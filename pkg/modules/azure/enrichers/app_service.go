package enrichers

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("app_services_public_access", enrichAppServicePublicAccess)
}

func enrichAppServicePublicAccess(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	appServiceName := result.ResourceName
	subscriptionID := result.SubscriptionID
	resourceGroupName := ParseResourceGroup(result.ResourceID)

	if appServiceName == "" {
		return []plugin.AzureEnrichmentCommand{{
			Description:  "Enrich publicly accessible App Service",
			ActualOutput: "Error: App Service name is empty",
			ExitCode:     1,
		}}, nil
	}

	httpClient := NewNoRedirectHTTPClient(10 * time.Second)
	var commands []plugin.AzureEnrichmentCommand

	// Step 1: HTTP probe to main page
	mainCmd := probeAppServiceMainPage(httpClient, appServiceName)
	commands = append(commands, mainCmd)

	// Step 2: SCM/Kudu probe
	scmCmd := probeSCMSite(httpClient, appServiceName)
	commands = append(commands, scmCmd)

	// Step 3: For function apps, enumerate triggers via Management API
	kind, _ := result.Properties["kind"].(string)
	isFunctionApp := strings.Contains(strings.ToLower(kind), "functionapp")

	if isFunctionApp && subscriptionID != "" && resourceGroupName != "" {
		mgmtCmds := enrichAppServiceFunctionApp(cfg, subscriptionID, resourceGroupName, appServiceName)
		commands = append(commands, mgmtCmds...)
	}

	return commands, nil
}

// probeAppServiceMainPage sends an HTTP GET to the App Service default page.
func probeAppServiceMainPage(client *http.Client, appName string) plugin.AzureEnrichmentCommand {
	appURL := fmt.Sprintf("https://%s.azurewebsites.net", appName)

	cmd := plugin.AzureEnrichmentCommand{
		Command:                   fmt.Sprintf("curl -i --max-redirects 0 '%s' --max-time 10", appURL),
		Description:               "Test HTTP GET to App Service default page",
		ExpectedOutputDescription: "200 = accessible | 3xx = redirect (auth) | 401/403 = auth required or stopped | timeout = blocked",
	}

	resp, err := client.Get(appURL)
	if err != nil {
		cmd.Error = err.Error()
		cmd.ActualOutput = fmt.Sprintf("Request failed: %s", err.Error())
		cmd.ExitCode = -1
		return cmd
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4000))
	bodyStr := string(body)

	title := ExtractHTMLTitle(bodyStr)

	var verdict string
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		verdict = "ACCESSIBLE"
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		location := resp.Header.Get("Location")
		verdict = fmt.Sprintf("REDIRECT to %s (likely auth gate)", location)
	case resp.StatusCode == 401:
		verdict = "AUTH REQUIRED (401)"
	case resp.StatusCode == 403:
		if strings.Contains(bodyStr, "stopped") || strings.Contains(bodyStr, "Unavailable") {
			verdict = "APP STOPPED (403 - Web App Unavailable)"
		} else {
			verdict = "FORBIDDEN (403)"
		}
	default:
		verdict = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}

	if title != "" {
		cmd.ActualOutput = fmt.Sprintf("Status: %d, %s\nPage title: %s", resp.StatusCode, verdict, title)
	} else {
		cmd.ActualOutput = fmt.Sprintf("Status: %d, %s\nBody preview: %s", resp.StatusCode, verdict, TruncateString(bodyStr, 200))
	}

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		cmd.ExitCode = 1
	case resp.StatusCode == 403 && (strings.Contains(bodyStr, "stopped") || strings.Contains(bodyStr, "Unavailable")):
		cmd.ExitCode = 0
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		cmd.ExitCode = 1
	default:
		cmd.ExitCode = 0
	}

	return cmd
}

// enrichAppServiceFunctionApp uses the Management API to enumerate HTTP triggers,
// check IP restrictions, and check EasyAuth for a function app embedded in an App Service.
func enrichAppServiceFunctionApp(cfg plugin.AzureEnricherConfig, subscriptionID, resourceGroupName, appName string) []plugin.AzureEnrichmentCommand {
	webAppsClient, err := NewWebAppsClient(subscriptionID, cfg.Credential)
	if err != nil {
		return []plugin.AzureEnrichmentCommand{{
			Description:  "Enumerate Function App triggers via Management API",
			ActualOutput: fmt.Sprintf("Error creating WebApps client: %s", err.Error()),
			ExitCode:     -1,
		}}
	}

	var commands []plugin.AzureEnrichmentCommand

	// Check IP restrictions
	ipCmd := checkIPRestrictionsCommand(cfg, webAppsClient, resourceGroupName, appName, "App Service")
	commands = append(commands, ipCmd)

	// Enumerate HTTP triggers
	cliEquiv := fmt.Sprintf("az functionapp function list --resource-group %s --name %s", resourceGroupName, appName)
	triggers, totalFunctions, err := ListHTTPTriggers(cfg.Context, webAppsClient, resourceGroupName, appName, "")
	if err != nil {
		commands = append(commands, plugin.AzureEnrichmentCommand{
			Command:      cliEquiv,
			Description:  "Enumerate Function App HTTP triggers via Management API",
			ActualOutput: fmt.Sprintf("Error: %s", err.Error()),
			ExitCode:     -1,
		})
		return commands
	}

	// Build trigger summary with auth level counts
	anonymousCount := 0
	functionKeyCount := 0
	adminKeyCount := 0
	for _, t := range triggers {
		switch strings.ToLower(t.AuthLevel) {
		case "anonymous":
			anonymousCount++
		case "function":
			functionKeyCount++
		case "admin":
			adminKeyCount++
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Function App: %s | Total functions: %d | HTTP triggers: %d\n", appName, totalFunctions, len(triggers)))
	sb.WriteString(fmt.Sprintf("Auth levels — Anonymous: %d | Function key: %d | Admin key: %d\n\n", anonymousCount, functionKeyCount, adminKeyCount))

	for _, t := range triggers {
		status := "enabled"
		if t.IsDisabled {
			status = "DISABLED"
		}
		methods := "ANY"
		if len(t.Methods) > 0 {
			methods = strings.Join(t.Methods, ", ")
		}
		sb.WriteString(fmt.Sprintf("  %-30s | auth=%-10s | route=%-25s | methods=%-10s | %s\n", t.FunctionName, t.AuthLevel, t.Route, methods, status))
		if t.InvokeURL != "" {
			sb.WriteString(fmt.Sprintf("  %-30s   invoke: %s\n", "", t.InvokeURL))
		}
	}

	if anonymousCount > 0 {
		sb.WriteString(fmt.Sprintf("\nFINDING: %d anonymous HTTP trigger(s) — no function key or auth token required", anonymousCount))
	} else if len(triggers) == 0 && totalFunctions > 0 {
		sb.WriteString("No HTTP triggers found — all functions use non-HTTP triggers (queue, timer, etc.)")
	} else if len(triggers) == 0 && totalFunctions == 0 {
		sb.WriteString("No functions deployed in this Function App")
	} else {
		sb.WriteString("All HTTP triggers require authentication (function key or admin key)")
	}

	exitCode := 0
	if anonymousCount > 0 {
		exitCode = 1
	}

	commands = append(commands, plugin.AzureEnrichmentCommand{
		Command:                   cliEquiv,
		Description:               "Enumerate Function App HTTP triggers via Management API",
		ExpectedOutputDescription: "Lists all HTTP triggers with auth levels, invoke URLs, and methods",
		ActualOutput:              sb.String(),
		ExitCode:                  exitCode,
	})

	// Check EasyAuth as compensating control
	easyAuthCmd := checkEasyAuthCommand(cfg, webAppsClient, resourceGroupName, appName)
	commands = append(commands, easyAuthCmd)

	return commands
}
