package enrichers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("app_services_public_access", enrichAppServicePublicAccess)
}

func enrichAppServicePublicAccess(_ plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	appServiceName := result.ResourceName

	if appServiceName == "" {
		return nil, nil
	}

	httpClient := NewNoRedirectHTTPClient(10 * time.Second)
	var commands []plugin.AzureEnrichmentCommand

	// Step 1: HTTP probe to main page
	mainCmd := probeAppServiceMainPage(httpClient, appServiceName)
	commands = append(commands, mainCmd)

	// Step 2: SCM/Kudu probe
	scmCmd := probeSCMSite(httpClient, appServiceName)
	commands = append(commands, scmCmd)

	return commands, nil
}

// probeAppServiceMainPage sends an HTTP GET to the App Service default page.
func probeAppServiceMainPage(client *http.Client, appName string) plugin.AzureEnrichmentCommand {
	appURL := fmt.Sprintf("https://%s.azurewebsites.net", appName)

	return ClassifiedHTTPProbe(client, appURL,
		fmt.Sprintf("curl -i --max-redirects 0 '%s' --max-time 10", appURL),
		"Test HTTP GET to App Service default page",
		"200 = accessible | 3xx = redirect (auth) | 401/403 = auth required or stopped | timeout = blocked",
		4000,
		func(r HTTPProbeResult) HTTPProbeClassification {
			title := ExtractHTMLTitle(r.Body)

			var verdict string
			switch {
			case r.StatusCode >= 200 && r.StatusCode < 300:
				verdict = "ACCESSIBLE"
			case r.StatusCode >= 300 && r.StatusCode < 400:
				location := r.Header.Get("Location")
				verdict = fmt.Sprintf("REDIRECT to %s (likely auth gate)", location)
			case r.StatusCode == 401:
				verdict = "AUTH REQUIRED (401)"
			case r.StatusCode == 403:
				if strings.Contains(r.Body, "stopped") || strings.Contains(r.Body, "Unavailable") {
					verdict = "APP STOPPED (403 - Web App Unavailable)"
				} else {
					verdict = "FORBIDDEN (403)"
				}
			default:
				verdict = fmt.Sprintf("HTTP %d", r.StatusCode)
			}

			var output string
			if title != "" {
				output = fmt.Sprintf("Status: %d, %s\nPage title: %s", r.StatusCode, verdict, title)
			} else {
				output = fmt.Sprintf("Status: %d, %s\nBody preview: %s", r.StatusCode, verdict, TruncateString(r.Body, 200))
			}

			var exitCode int
			switch {
			case r.StatusCode >= 200 && r.StatusCode < 300:
				exitCode = 1
			case r.StatusCode == 403 && (strings.Contains(r.Body, "stopped") || strings.Contains(r.Body, "Unavailable")):
				exitCode = 0
			case r.StatusCode == 401 || r.StatusCode == 403:
				exitCode = 1
			default:
				exitCode = 0
			}

			return HTTPProbeClassification{ExitCode: exitCode, ActualOutput: output}
		},
	)
}

