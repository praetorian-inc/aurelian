package enricher

import (
	"context"
	"fmt"
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

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Test anonymous access via HTTP request
	testURL := fmt.Sprintf("https://%s.blob.core.windows.net/?comp=list", storageAccountNameForURL)

	resp, err := client.Get(testURL)

	command := fmt.Sprintf("curl -w '\n===== Status Code =====\n%%{http_code}\n' '%s' --max-time 10", testURL)
	curlCommand := Command{
		Command:                   command,
		Description:               "Test anonymous access to storage account container listing",
		ExpectedOutputDescription: "anonymous access enabled 404 | anonymous access disabled = 401/403 | public access disabled = 409",
	}

	if err != nil {
		curlCommand.Error = err.Error()
		curlCommand.ActualOutput = fmt.Sprintf("Request failed: %s", err.Error())
	} else {
		defer resp.Body.Close()
		curlCommand.ActualOutput = fmt.Sprintf("HTTP %d", resp.StatusCode)
		curlCommand.ExitCode = resp.StatusCode
	}

	commands = append(commands, curlCommand)
	return commands
}
