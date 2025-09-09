package enricher

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// AKSClusterEnricher implements enrichment for AKS Cluster instances
type AKSClusterEnricher struct{}

func (a *AKSClusterEnricher) CanEnrich(templateID string) bool {
	return templateID == "aks_public_access"
}

func (a *AKSClusterEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	// Extract AKS cluster name
	clusterName := resource.Name
	resourceGroup := resource.ResourceGroup

	if clusterName == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "Missing AKS cluster name",
			ActualOutput: "Error: AKS cluster name is empty",
		})
		return commands
	}

	// Test 1: Test direct HTTP access to Kubernetes endpoint
	fqdn := resource.Properties["fqdn"]
	if fqdn == "" {
		fqdn = "UNDEFINED_FQDN"
	}

	// Create HTTP client with timeout and skip SSL verification
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}

	// Test anonymous access via HTTP request
	testURL := fmt.Sprintf("https://%s", fqdn)

	resp, err := client.Get(testURL)

	command := fmt.Sprintf("curl -k -i '%s' --max-time 10", testURL)
	curlCommand := Command{
		Command:                   command,
		Description:               fmt.Sprintf("Test direct HTTP access to Kubernetes endpoint: %s", fqdn),
		ExpectedOutputDescription: "200 = anonymous access enabled | 401/403 = authentication required | timeout = blocked",
	}

	if err != nil {
		curlCommand.Error = err.Error()
		curlCommand.ActualOutput = fmt.Sprintf("Request failed: %s", err.Error())
	} else {
		defer resp.Body.Close()
		// Read response body (limit to first 1000 characters for safety)
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1000))
		if readErr != nil {
			curlCommand.ActualOutput = fmt.Sprintf("Body read error: %s", readErr.Error())
		} else {
			curlCommand.ActualOutput = fmt.Sprintf("Status: %d, Body: %s", resp.StatusCode, string(body))
		}
		curlCommand.ExitCode = resp.StatusCode
	}

	commands = append(commands, curlCommand)

	// Test 2: Azure CLI command to show AKS cluster details
	azShowCommand := Command{
		Command:                   fmt.Sprintf("az aks show --resource-group %s --name %s", resourceGroup, clusterName),
		Description:               "Azure CLI command to get AKS cluster access configuration",
		ExpectedOutputDescription: "Cluster config details = API server FQDN and access settings | Error = access denied",
		ActualOutput:              "Manual execution required - provides API server FQDN for testing",
	}

	commands = append(commands, azShowCommand)

	return commands
}
