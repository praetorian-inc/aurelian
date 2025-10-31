package enricher

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// StorageAccountEnricher implements enrichment for storage accounts
type StorageAccountEnricher struct{}

func (s *StorageAccountEnricher) CanEnrich(templateID string) bool {
	return templateID == "storage_accounts_public_access"
}

func (s *StorageAccountEnricher) Enrich(ctx context.Context, resource *model.AzureResource) []Command {
	commands := []Command{}

	// Extract storage account name from resource
	storageAccountName := resource.Name
	if storageAccountName == "" {
		commands = append(commands, Command{
			Command:      "",
			Description:  "No storage account name found",
			ActualOutput: "Error: storage account name is empty",
		})
		return commands
	}

	// Sanitize the storage account name for URL encoding
	storageAccountNameForURL := url.QueryEscape(strings.TrimSpace(storageAccountName))

	// Create HTTP client with timeout (reduced from 10s for better performance)
	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	// Test anonymous access via HTTP request
	testURL := fmt.Sprintf("https://%s.blob.core.windows.net/?comp=list", storageAccountNameForURL)

	resp, err := client.Get(testURL)

	command := fmt.Sprintf("curl -i '%s' --max-time 10", testURL)
	curlCommand := Command{
		Command:                   command,
		Description:               "Test anonymous access to storage account container listing",
		ExpectedOutputDescription: "anonymous access enabled = 404 | anonymous access disabled = 401/403 | public access disabled = 409",
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
			curlCommand.ActualOutput = fmt.Sprintf("Body: %s", string(body))
		}
		curlCommand.ExitCode = resp.StatusCode
	}

	commands = append(commands, curlCommand)
	return commands
}
