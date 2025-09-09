package enricher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// AppServiceEnricher implements enrichment for App Service instances
type AppServiceEnricher struct{}

func (a *AppServiceEnricher) CanEnrich(templateID string) bool {
	return templateID == "app_services_public_access"
}

func (a *AppServiceEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	// Extract App Service name
	appServiceName := resource.Name
	if appServiceName == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing App Service name",
			ActualOutput: "Error: App Service name is empty",
		})
		return commands
	}

	// Construct App Service URL
	appServiceURL := fmt.Sprintf("https://%s.azurewebsites.net", appServiceName)

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow more than 5 redirects
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	// Test 1: HTTP GET to main page
	resp, err := client.Get(appServiceURL)

	httpGetCommand := Command{
		Command:                   fmt.Sprintf("curl -i -L '%s' --max-time 10", appServiceURL),
		Description:               "Test HTTP GET to App Service default page",
		ExpectedOutputDescription: "200 = accessible | 401/403 = authentication required | 404 = not found but accessible | 503 = app stopped/error",
	}

	if err != nil {
		httpGetCommand.Error = err.Error()
		httpGetCommand.ActualOutput = fmt.Sprintf("Request failed: %s", err.Error())
		httpGetCommand.ExitCode = -1
	} else {
		defer resp.Body.Close()
		// Read full response body (limit to first 2000 characters for App Service responses)
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 2000))
		if readErr != nil {
			httpGetCommand.ActualOutput = fmt.Sprintf("Body read error: %s", readErr.Error())
		} else {
			httpGetCommand.ActualOutput = fmt.Sprintf("Body: %s", string(body))
		}
		httpGetCommand.ExitCode = resp.StatusCode
	}

	commands = append(commands, httpGetCommand)

	// Test 2: Check for SCM/Kudu site (if accessible)
	scmURL := fmt.Sprintf("https://%s.scm.azurewebsites.net", appServiceName)

	scmResp, scmErr := client.Get(scmURL)

	scmCommand := Command{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 10", scmURL),
		Description:               "Test access to SCM/Kudu management site",
		ExpectedOutputDescription: "200 = SCM accessible (high risk) | 401/403 = authentication required | timeout = blocked",
	}

	if scmErr != nil {
		scmCommand.Error = scmErr.Error()
		scmCommand.ActualOutput = fmt.Sprintf("Request failed: %s", scmErr.Error())
		scmCommand.ExitCode = -1
	} else {
		defer scmResp.Body.Close()
		// Read SCM response body
		body, readErr := io.ReadAll(io.LimitReader(scmResp.Body, 1000))
		if readErr != nil {
			scmCommand.ActualOutput = fmt.Sprintf("Body read error: %s", readErr.Error())
		} else {
			scmCommand.ActualOutput = fmt.Sprintf("Body: %s", string(body))
		}
		scmCommand.ExitCode = scmResp.StatusCode
	}

	commands = append(commands, scmCommand)

	return commands
}

// Helper function to extract domain from URL
func extractDomain(urlStr string) string {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}
	return parsedURL.Host
}
