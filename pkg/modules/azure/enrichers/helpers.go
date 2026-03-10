package enrichers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v4"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// ParseResourceGroup extracts the resource group name from an Azure resource ID.
// For example, "/subscriptions/.../resourceGroups/myRG/providers/..." returns "myRG".
// Returns an empty string if the resource ID does not contain a resource group segment.
func ParseResourceGroup(resourceID string) string {
	parts := strings.Split(resourceID, "/")
	for i, p := range parts {
		if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// TruncateString limits s to maxLen characters. If the string is truncated,
// "..." is appended (the total length will be maxLen + 3).
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// NewHTTPClient returns an *http.Client configured with the given timeout.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout}
}

// NewNoRedirectHTTPClient returns an *http.Client that does not follow redirects.
func NewNoRedirectHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// HTTPProbe performs an HTTP GET request and returns an AzureEnrichmentCommand
// capturing the result. curlEquiv is the shell-equivalent command shown in the
// Command field. description and expectedOutput populate the corresponding
// fields on the returned command.
func HTTPProbe(client *http.Client, url, curlEquiv, description, expectedOutput string) plugin.AzureEnrichmentCommand {
	cmd := plugin.AzureEnrichmentCommand{
		Command:                   curlEquiv,
		Description:               description,
		ExpectedOutputDescription: expectedOutput,
	}

	resp, err := client.Get(url)
	if err != nil {
		cmd.ExitCode = 1
		cmd.Error = err.Error()
		return cmd
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1000))
	if err != nil {
		cmd.ExitCode = 1
		cmd.Error = fmt.Sprintf("reading body: %s", err.Error())
		return cmd
	}

	cmd.ActualOutput = fmt.Sprintf("HTTP %d\n%s", resp.StatusCode, string(body))
	cmd.ExitCode = 0
	return cmd
}

// TCPProbe tests TCP connectivity to host:port with the given timeout and
// returns an AzureEnrichmentCommand with the result.
func TCPProbe(host string, port int, timeout time.Duration) plugin.AzureEnrichmentCommand {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	cmd := plugin.AzureEnrichmentCommand{
		Command:                   fmt.Sprintf("nc -zv %s %d", host, port),
		Description:               fmt.Sprintf("TCP connectivity check to %s", addr),
		ExpectedOutputDescription: "Connection succeeded or refused",
	}

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		cmd.ExitCode = 1
		cmd.Error = err.Error()
		cmd.ActualOutput = fmt.Sprintf("Connection to %s failed: %s", addr, err.Error())
		return cmd
	}
	conn.Close()

	cmd.ExitCode = 0
	cmd.ActualOutput = fmt.Sprintf("Connection to %s succeeded", addr)
	return cmd
}

// HTTPTriggerInfo holds parsed HTTP trigger metadata for an Azure Function App function.
type HTTPTriggerInfo struct {
	FunctionName string   `json:"functionName"`
	AuthLevel    string   `json:"authLevel"`
	InvokeURL    string   `json:"invokeURL"`
	Route        string   `json:"route"`
	Methods      []string `json:"methods"`
	IsDisabled   bool     `json:"isDisabled"`
	SlotName     string   `json:"slotName"`
}

// ListHTTPTriggers enumerates HTTP-triggered functions for an Azure Function App
// via the Management API. If slotName is empty, the production slot is used.
func ListHTTPTriggers(ctx context.Context, client *armappservice.WebAppsClient, resourceGroup, appName, slotName string) ([]HTTPTriggerInfo, int, error) {
	var triggers []HTTPTriggerInfo
	totalFunctions := 0

	if slotName == "" || strings.EqualFold(slotName, "production") {
		p := client.NewListFunctionsPager(resourceGroup, appName, nil)
		for p.More() {
			page, err := p.NextPage(ctx)
			if err != nil {
				return nil, 0, fmt.Errorf("listing functions: %w", err)
			}
			for _, fn := range page.Value {
				totalFunctions++
				trigger := parseHTTPTrigger(fn, appName, slotName)
				if trigger != nil {
					triggers = append(triggers, *trigger)
				}
			}
		}
	} else {
		p := client.NewListInstanceFunctionsSlotPager(resourceGroup, appName, slotName, nil)
		for p.More() {
			page, err := p.NextPage(ctx)
			if err != nil {
				return nil, 0, fmt.Errorf("listing slot functions: %w", err)
			}
			for _, fn := range page.Value {
				totalFunctions++
				trigger := parseHTTPTrigger(fn, appName, slotName)
				if trigger != nil {
					triggers = append(triggers, *trigger)
				}
			}
		}
	}

	return triggers, totalFunctions, nil
}

// parseHTTPTrigger inspects a FunctionEnvelope for httpTrigger bindings and
// returns an HTTPTriggerInfo if found.
func parseHTTPTrigger(fn *armappservice.FunctionEnvelope, appName, slotName string) *HTTPTriggerInfo {
	if fn == nil || fn.Properties == nil {
		return nil
	}

	props := fn.Properties

	// Extract function name from the resource ID or Name field.
	funcName := ""
	if fn.Name != nil {
		// Name is typically "appName/functionName"
		parts := strings.Split(*fn.Name, "/")
		funcName = parts[len(parts)-1]
	}

	// Check if the function is disabled.
	isDisabled := false
	if cfg, ok := props.Config.(map[string]interface{}); ok {
		if disabled, ok := cfg["disabled"].(bool); ok {
			isDisabled = disabled
		}
	}

	// Parse bindings to find httpTrigger.
	cfg, ok := props.Config.(map[string]interface{})
	if !ok {
		return nil
	}
	bindings, ok := cfg["bindings"].([]interface{})
	if !ok {
		return nil
	}

	for _, b := range bindings {
		binding, ok := b.(map[string]interface{})
		if !ok {
			continue
		}
		bType, _ := binding["type"].(string)
		if !strings.EqualFold(bType, "httpTrigger") {
			continue
		}

		authLevel, _ := binding["authLevel"].(string)
		route, _ := binding["route"].(string)

		var methods []string
		if m, ok := binding["methods"].([]interface{}); ok {
			for _, method := range m {
				if s, ok := method.(string); ok {
					methods = append(methods, s)
				}
			}
		}

		// Build invoke URL.
		host := fmt.Sprintf("%s.azurewebsites.net", appName)
		if slotName != "" && !strings.EqualFold(slotName, "production") {
			host = fmt.Sprintf("%s-%s.azurewebsites.net", appName, slotName)
		}
		path := route
		if path == "" {
			path = "api/" + funcName
		}
		invokeURL := fmt.Sprintf("https://%s/%s", host, path)

		return &HTTPTriggerInfo{
			FunctionName: funcName,
			AuthLevel:    authLevel,
			InvokeURL:    invokeURL,
			Route:        route,
			Methods:      methods,
			IsDisabled:   isDisabled,
			SlotName:     slotName,
		}
	}

	return nil
}

// EasyAuthStatus represents the result of an Easy Auth configuration check.
type EasyAuthStatus struct {
	Enabled bool
	Err     error
}

// CheckEasyAuth queries the App Service Authentication V2 settings for the
// given app and returns whether Easy Auth is enabled.
func CheckEasyAuth(ctx context.Context, client *armappservice.WebAppsClient, resourceGroup, appName string) EasyAuthStatus {
	resp, err := client.GetAuthSettingsV2(ctx, resourceGroup, appName, nil)
	if err != nil {
		return EasyAuthStatus{Err: fmt.Errorf("getting auth settings: %w", err)}
	}

	if resp.Properties != nil &&
		resp.Properties.Platform != nil &&
		resp.Properties.Platform.Enabled != nil &&
		*resp.Properties.Platform.Enabled {
		return EasyAuthStatus{Enabled: true}
	}

	return EasyAuthStatus{Enabled: false}
}

// NewWebAppsClient creates an armappservice.WebAppsClient from a subscription
// ID and token credential.
func NewWebAppsClient(subscriptionID string, cred azcore.TokenCredential) (*armappservice.WebAppsClient, error) {
	client, err := armappservice.NewWebAppsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("creating web apps client: %w", err)
	}
	return client, nil
}

// ExtractHTMLTitle extracts the content of the <title> tag from an HTML body.
// Returns an empty string if no title tag is found.
func ExtractHTMLTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title")
	if start == -1 {
		return ""
	}
	// Skip past the closing '>' of the opening tag.
	closeTag := strings.Index(lower[start:], ">")
	if closeTag == -1 {
		return ""
	}
	contentStart := start + closeTag + 1

	end := strings.Index(lower[contentStart:], "</title")
	if end == -1 {
		return ""
	}

	return strings.TrimSpace(body[contentStart : contentStart+end])
}

// derefString safely dereferences a string pointer, returning "" if nil.
func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// probeSCMSite tests the SCM/Kudu management endpoint for an App Service or Function App.
func probeSCMSite(client *http.Client, appName string) plugin.AzureEnrichmentCommand {
	scmURL := fmt.Sprintf("https://%s.scm.azurewebsites.net", appName)

	cmd := plugin.AzureEnrichmentCommand{
		Command:                   fmt.Sprintf("curl -i --max-redirects 0 '%s' --max-time 10", scmURL),
		Description:               "Test access to SCM/Kudu management site (high risk if accessible)",
		ExpectedOutputDescription: "200 = SCM accessible (HIGH RISK) | 3xx = redirect (auth) | 401/403 = auth required | timeout = blocked",
	}

	resp, err := client.Get(scmURL)
	if err != nil {
		cmd.Error = err.Error()
		cmd.ActualOutput = fmt.Sprintf("Request failed: %s", err.Error())
		cmd.ExitCode = -1
		return cmd
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1000))

	var exitCode int
	var verdict string
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		exitCode = 1
		verdict = "SCM ACCESSIBLE (HIGH RISK)"
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		exitCode = 0
		verdict = "Redirect (auth required)"
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		exitCode = 0
		verdict = "Auth required"
	default:
		exitCode = 0
		verdict = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}

	cmd.ActualOutput = fmt.Sprintf("HTTP %d — %s\nBody preview: %s", resp.StatusCode, verdict, TruncateString(string(body), 500))
	cmd.ExitCode = exitCode

	return cmd
}

// checkIPRestrictionsCommand queries IP security restrictions via the Management API.
// resourceLabel is used in messages (e.g. "App Service" or "Function App").
func checkIPRestrictionsCommand(cfg plugin.AzureEnricherConfig, client *armappservice.WebAppsClient, resourceGroup, appName, resourceLabel string) plugin.AzureEnrichmentCommand {
	cmd := plugin.AzureEnrichmentCommand{
		Command:                   fmt.Sprintf("az webapp config access-restriction show --resource-group %s --name %s", resourceGroup, appName),
		Description:               "Check IP security restrictions via Management API (not available in ARG)",
		ExpectedOutputDescription: "IP restrictions present = lower severity | No restrictions = fully open to internet",
	}

	siteConfig, err := client.GetConfiguration(cfg.Context, resourceGroup, appName, nil)
	if err != nil {
		cmd.Error = err.Error()
		cmd.ActualOutput = fmt.Sprintf("Error getting site configuration: %s", err.Error())
		cmd.ExitCode = -1
		return cmd
	}

	if siteConfig.Properties == nil || siteConfig.Properties.IPSecurityRestrictions == nil {
		cmd.ActualOutput = fmt.Sprintf("No IP restrictions configured — %s is fully open to all internet traffic.", resourceLabel)
		cmd.ExitCode = 1
		return cmd
	}

	restrictions := siteConfig.Properties.IPSecurityRestrictions

	// Filter out the default "Allow all" rule (priority 2147483647)
	var meaningful []*armappservice.IPSecurityRestriction
	for _, r := range restrictions {
		if r.Priority != nil && *r.Priority == 2147483647 {
			continue
		}
		meaningful = append(meaningful, r)
	}

	if len(meaningful) == 0 {
		cmd.ActualOutput = fmt.Sprintf("No IP restrictions configured — %s is fully open to all internet traffic.", resourceLabel)
		cmd.ExitCode = 1
		return cmd
	}

	// Check if any meaningful rule is a broad allow-all
	for _, r := range meaningful {
		if r.Action != nil && strings.EqualFold(*r.Action, "Allow") {
			if r.IPAddress != nil {
				ip := strings.TrimSpace(*r.IPAddress)
				if ip == "0.0.0.0/0" || ip == "::/0" {
					cmd.ActualOutput = fmt.Sprintf("No effective IP restrictions — broad allow-all rule (0.0.0.0/0) present. %s is open to all internet traffic.", resourceLabel)
					cmd.ExitCode = 1
					return cmd
				}
			}
			if r.Tag != nil && *r.Tag == armappservice.IPFilterTagServiceTag && r.IPAddress != nil {
				if strings.EqualFold(strings.TrimSpace(*r.IPAddress), "Internet") {
					cmd.ActualOutput = fmt.Sprintf("No effective IP restrictions — Allow rule with ServiceTag 'Internet' present. %s is open to all internet traffic.", resourceLabel)
					cmd.ExitCode = 1
					return cmd
				}
			}
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("IP restrictions found: %d rule(s)\n", len(meaningful)))
	for _, r := range meaningful {
		sb.WriteString(fmt.Sprintf("  [%d] %s: %s %s\n",
			derefInt32(r.Priority), derefString(r.Name), derefString(r.Action), derefString(r.IPAddress)))
	}
	sb.WriteString("\nIP restrictions are present — network-level filtering is in place.")

	cmd.ActualOutput = sb.String()
	cmd.ExitCode = 0
	return cmd
}

// derefInt32 safely dereferences an int32 pointer, returning 0 if nil.
func derefInt32(p *int32) int32 {
	if p == nil {
		return 0
	}
	return *p
}

// checkEasyAuthCommand queries EasyAuth / Entra ID platform authentication status.
func checkEasyAuthCommand(cfg plugin.AzureEnricherConfig, client *armappservice.WebAppsClient, resourceGroup, appName string) plugin.AzureEnrichmentCommand {
	cmd := plugin.AzureEnrichmentCommand{
		Command:                   fmt.Sprintf("az webapp auth show --resource-group %s --name %s", resourceGroup, appName),
		Description:               "Check EasyAuth / Entra ID platform authentication",
		ExpectedOutputDescription: "Enabled = compensating control | Disabled = anonymous triggers are truly unauthenticated",
	}

	status := CheckEasyAuth(cfg.Context, client, resourceGroup, appName)
	if status.Err != nil {
		cmd.Error = status.Err.Error()
		cmd.ActualOutput = fmt.Sprintf("Error checking EasyAuth: %s", status.Err.Error())
		cmd.ExitCode = -1
		return cmd
	}

	if status.Enabled {
		cmd.ActualOutput = "EasyAuth is ENABLED — platform enforces authentication before requests reach function code. Anonymous trigger auth levels are overridden by EasyAuth."
		cmd.ExitCode = 0
	} else {
		cmd.ActualOutput = "EasyAuth is DISABLED — no platform-level authentication. Anonymous triggers are truly accessible without any authentication."
		cmd.ExitCode = 1
	}

	return cmd
}

// firewallRuleOutput represents a firewall rule in the format expected by Azure CLI output.
type firewallRuleOutput struct {
	EndIPAddress   string `json:"endIpAddress"`
	ID             string `json:"id"`
	Name           string `json:"name"`
	ResourceGroup  string `json:"resourceGroup"`
	StartIPAddress string `json:"startIpAddress"`
	Type           string `json:"type"`
}

// buildFirewallRulesCommand creates an enrichment command that fetches firewall rules
// using the provided callback and formats them as JSON.
func buildFirewallRulesCommand(azCommand, description string, fetchRules func() ([]firewallRuleOutput, error)) plugin.AzureEnrichmentCommand {
	rules, err := fetchRules()
	if err != nil {
		return plugin.AzureEnrichmentCommand{
			Command:      azCommand,
			Description:  description + " (SDK failed)",
			ActualOutput: fmt.Sprintf("SDK retrieval failed: %s", err.Error()),
			Error:        err.Error(),
			ExitCode:     1,
		}
	}

	output := "[]"
	if len(rules) > 0 {
		b, err := json.MarshalIndent(rules, "", "  ")
		if err != nil {
			output = fmt.Sprintf("Error formatting output: %s", err.Error())
		} else {
			output = string(b)
		}
	}

	return plugin.AzureEnrichmentCommand{
		Command:                   azCommand,
		Description:               description,
		ExpectedOutputDescription: "List of firewall rules with names and IP address ranges",
		ActualOutput:              output,
		ExitCode:                  0,
	}
}

// enrichEventGridPOSTEndpoint tests an Event Grid endpoint by POSTing an empty events array.
// endpointFromProps is the endpoint extracted from resource properties (may be empty).
func enrichEventGridPOSTEndpoint(ctx context.Context, resourceName, location, endpointFromProps, description string) ([]plugin.AzureEnrichmentCommand, error) {
	var endpoint string
	if endpointFromProps != "" {
		endpoint = endpointFromProps
		if !strings.HasSuffix(endpoint, "/api/events") {
			endpoint = strings.TrimSuffix(endpoint, "/") + "/api/events"
		}
	} else {
		if location == "" || resourceName == "" {
			return nil, nil
		}
		normalizedLocation := strings.TrimSpace(strings.ToLower(location))
		endpoint = fmt.Sprintf("https://%s.%s-1.eventgrid.azure.net/api/events", resourceName, normalizedLocation)
	}

	client := NewHTTPClient(10 * time.Second)

	body := bytes.NewBuffer([]byte("[]"))
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, body)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("Content-Type", "application/json")

	cmd := plugin.AzureEnrichmentCommand{
		Command:                   fmt.Sprintf("curl -X POST -H 'Content-Type: application/json' -d '[]' -i '%s' --max-time 10", endpoint),
		Description:               description,
		ExpectedOutputDescription: "401/405 = publicly accessible but authentication required | 403 = blocked via firewall rules",
	}

	resp, err := client.Do(req)
	if err != nil {
		cmd.ExitCode = 1
		cmd.Error = err.Error()
	} else {
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		cmd.ActualOutput = fmt.Sprintf("HTTP %d", resp.StatusCode)
		cmd.ExitCode = 0
	}

	return []plugin.AzureEnrichmentCommand{cmd}, nil
}
