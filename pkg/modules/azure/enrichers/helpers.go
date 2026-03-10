package enrichers

import (
	"context"
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
