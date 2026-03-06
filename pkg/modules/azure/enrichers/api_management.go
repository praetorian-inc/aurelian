package enrichers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("api_management_public_access", enrichAPIManagement)
	plugin.RegisterAzureEnricher("apim_cross_tenant_signup_bypass", enrichAPIManagement)
}

// apimSignupPayload represents the test payload for the signup API.
type apimSignupPayload struct {
	Challenge  apimSignupChallenge `json:"challenge"`
	SignupData apimSignupData      `json:"signupData"`
}

type apimSignupChallenge struct {
	TestCaptchaRequest apimCaptchaRequest `json:"testCaptchaRequest"`
	AzureRegion        string             `json:"azureRegion"`
	ChallengeType      string             `json:"challengeType"`
}

type apimCaptchaRequest struct {
	ChallengeID   string `json:"challengeId"`
	InputSolution string `json:"inputSolution"`
}

type apimSignupData struct {
	Email        string `json:"email"`
	FirstName    string `json:"firstName"`
	LastName     string `json:"lastName"`
	Password     string `json:"password"`
	Confirmation string `json:"confirmation"`
	AppType      string `json:"appType"`
}

func enrichAPIManagement(_ plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	apimName := result.ResourceName
	if apimName == "" {
		return []plugin.AzureEnrichmentCommand{{
			Description:  "Missing APIM name",
			ActualOutput: "Error: APIM name is empty",
		}}, nil
	}

	resourceGroup := ParseResourceGroup(result.ResourceID)

	// Extract gateway URL from properties with fallback
	var gatewayURL string
	if gwURL, ok := result.Properties["gatewayUrl"].(string); ok && gwURL != "" {
		gatewayURL = gwURL
	} else {
		gatewayURL = fmt.Sprintf("https://%s.azure-api.net", apimName)
	}
	gatewayURL = strings.TrimSuffix(gatewayURL, "/")

	// Extract developer portal URL from properties (no fallback - may not exist)
	var developerPortalURL string
	if portalURL, ok := result.Properties["developerPortalUrl"].(string); ok && portalURL != "" {
		developerPortalURL = strings.TrimSuffix(portalURL, "/")
	}

	client := NewHTTPClient(15 * time.Second)

	var commands []plugin.AzureEnrichmentCommand

	// Test 1: Check if gateway endpoint is accessible
	gatewayCmd := apimTestGatewayAccess(client, gatewayURL)
	commands = append(commands, gatewayCmd)

	// Tests 2-4: Developer portal tests (only if developer portal exists)
	if developerPortalURL != "" {
		portalCmd := apimTestPortalAccess(client, developerPortalURL)
		commands = append(commands, portalCmd)

		signupPageCmd := apimTestSignupPageAccess(client, developerPortalURL)
		commands = append(commands, signupPageCmd)

		signupAPICmd := apimTestSignupAPI(client, developerPortalURL)
		commands = append(commands, signupAPICmd)
	} else {
		commands = append(commands, plugin.AzureEnrichmentCommand{
			Description:  "Developer portal URL not found in resource properties",
			ActualOutput: "Developer portal URL not found in resource properties - likely Consumption tier (no developer portal). Signup vulnerability tests skipped.",
			ExitCode:     0,
		})
	}

	// Add Azure CLI command for manual inspection
	if resourceGroup != "" {
		azCmd := plugin.AzureEnrichmentCommand{
			Command:                   fmt.Sprintf("az apim show --name %s --resource-group %s", apimName, resourceGroup),
			Description:               "Get full APIM configuration via Azure CLI",
			ExpectedOutputDescription: "Shows complete APIM configuration including SKU tier",
		}
		commands = append(commands, azCmd)
	}

	return commands, nil
}

func apimTestGatewayAccess(client *http.Client, gatewayURL string) plugin.AzureEnrichmentCommand {
	cmd := plugin.AzureEnrichmentCommand{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 15", gatewayURL),
		Description:               "Test if APIM gateway endpoint is accessible",
		ExpectedOutputDescription: "401 = authentication required | 200 = gateway accessible | 403 = blocked",
	}

	resp, err := client.Get(gatewayURL)
	if err != nil {
		cmd.Error = err.Error()
		cmd.ActualOutput = fmt.Sprintf("Request failed: %s", err.Error())
		cmd.ExitCode = -1
		return cmd
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1000))
	cmd.ActualOutput = fmt.Sprintf("Status: %d, Body preview: %s", resp.StatusCode, TruncateString(string(body), 500))
	cmd.ExitCode = resp.StatusCode

	return cmd
}

func apimTestPortalAccess(client *http.Client, baseURL string) plugin.AzureEnrichmentCommand {
	cmd := plugin.AzureEnrichmentCommand{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 15", baseURL),
		Description:               "Test if Developer Portal is accessible",
		ExpectedOutputDescription: "200 = portal accessible | 403 = blocked | timeout = not reachable",
	}

	resp, err := client.Get(baseURL)
	if err != nil {
		cmd.Error = err.Error()
		cmd.ActualOutput = fmt.Sprintf("Request failed: %s", err.Error())
		cmd.ExitCode = -1
		return cmd
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1000))
	cmd.ActualOutput = fmt.Sprintf("Status: %d, Body preview: %s", resp.StatusCode, TruncateString(string(body), 500))
	cmd.ExitCode = resp.StatusCode

	return cmd
}

func apimTestSignupPageAccess(client *http.Client, baseURL string) plugin.AzureEnrichmentCommand {
	signupURL := baseURL + "/signup"

	cmd := plugin.AzureEnrichmentCommand{
		Command:                   fmt.Sprintf("curl -i '%s' --max-time 15", signupURL),
		Description:               "Test if signup page is accessible (UI check)",
		ExpectedOutputDescription: "200 = signup visible in UI | 404 = signup hidden in UI (but API may still work!) | redirect = disabled",
	}

	resp, err := client.Get(signupURL)
	if err != nil {
		cmd.Error = err.Error()
		cmd.ActualOutput = fmt.Sprintf("Request failed: %s", err.Error())
		cmd.ExitCode = -1
		return cmd
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 500))
	cmd.ActualOutput = fmt.Sprintf("Status: %d, Body preview: %s", resp.StatusCode, TruncateString(string(body), 300))
	cmd.ExitCode = resp.StatusCode

	return cmd
}

func apimTestSignupAPI(client *http.Client, baseURL string) plugin.AzureEnrichmentCommand {
	signupURL := baseURL + "/signup"

	payload := apimSignupPayload{
		Challenge: apimSignupChallenge{
			TestCaptchaRequest: apimCaptchaRequest{
				ChallengeID:   "00000000-0000-0000-0000-000000000000",
				InputSolution: "AAAAAA",
			},
			AzureRegion:   "NorthCentralUS",
			ChallengeType: "visual",
		},
		SignupData: apimSignupData{
			Email:        "aurelian-vuln-probe@nonexistent-invalid-domain.test",
			FirstName:    "Aurelian",
			LastName:     "Probe",
			Password:     "AurelianProbe123!",
			Confirmation: "signup",
			AppType:      "developerPortal",
		},
	}

	payloadBytes, _ := json.Marshal(payload)

	curlCmd := fmt.Sprintf(`curl -X POST '%s' \
  -H 'Content-Type: application/json' \
  -H 'Origin: %s' \
  --data-raw '%s' --max-time 15`, signupURL, baseURL, string(payloadBytes))

	cmd := plugin.AzureEnrichmentCommand{
		Command:     curlCmd,
		Description: "Test signup API endpoint directly (VULNERABILITY TEST - GHSA-vcwf-73jp-r7mv)",
		ExpectedOutputDescription: `400 with captcha/challenge error = VULNERABLE (API active despite UI disabled)
404 = NOT vulnerable (API disabled)
200/201 = CRITICAL - signup succeeded!
409 = VULNERABLE (conflict/duplicate)`,
	}

	req, err := http.NewRequest("POST", signupURL, bytes.NewReader(payloadBytes))
	if err != nil {
		cmd.Error = err.Error()
		cmd.ActualOutput = fmt.Sprintf("Failed to create request: %s", err.Error())
		cmd.ExitCode = -1
		return cmd
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Origin", baseURL)
	req.Header.Set("Referer", signupURL)

	resp, err := client.Do(req)
	if err != nil {
		cmd.Error = err.Error()
		cmd.ActualOutput = fmt.Sprintf("Request failed: %s", err.Error())
		cmd.ExitCode = -1
		return cmd
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1500))
	bodyStr := string(body)
	bodyLower := strings.ToLower(bodyStr)

	var vulnStatus string
	switch {
	case resp.StatusCode == 404:
		vulnStatus = "NOT VULNERABLE - Signup API not found (disabled)"
	case resp.StatusCode == 400:
		if strings.Contains(bodyLower, "captcha") || strings.Contains(bodyLower, "challenge") {
			vulnStatus = "VULNERABLE - Signup API is ACTIVE (captcha validation response)"
		} else if strings.Contains(bodyLower, "email") || strings.Contains(bodyLower, "password") || strings.Contains(bodyLower, "invalid") || strings.Contains(bodyLower, "validation") {
			vulnStatus = "VULNERABLE - Signup API is ACTIVE (input validation response)"
		} else {
			vulnStatus = "LIKELY VULNERABLE - Signup API responds to requests"
		}
	case resp.StatusCode == 409:
		vulnStatus = "VULNERABLE - Signup API is ACTIVE (conflict response)"
	case resp.StatusCode == 200 || resp.StatusCode == 201:
		vulnStatus = "CRITICAL - Signup API ACCEPTS registrations!"
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		vulnStatus = "API responds but requires auth - further investigation needed"
	case resp.StatusCode == 422:
		vulnStatus = "VULNERABLE - Signup API validates input (422 response)"
	default:
		vulnStatus = fmt.Sprintf("Unexpected response (%d) - manual investigation needed", resp.StatusCode)
	}

	cmd.ActualOutput = fmt.Sprintf("ASSESSMENT: %s\n\nStatus: %d\nResponse: %s",
		vulnStatus, resp.StatusCode, TruncateString(bodyStr, 800))
	cmd.ExitCode = resp.StatusCode

	return cmd
}
