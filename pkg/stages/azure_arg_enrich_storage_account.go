package stages

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/nebula/pkg/templates"
)

func enrichStorageAccount(ctx context.Context, result *templates.ARGQueryResult) []templates.Command {
	commands := []templates.Command{}

	// Extract storage account name from the result
	storageAccountName := result.ResourceName
	if storageAccountName == "" {
		// Fallback to name field if resourceName is empty
		storageAccountName = result.Name
	}
	// Add validation and debugging
	if storageAccountName == "" {
		commands = append(commands, templates.Command{
			Command:      "",
			Description:  "No storage account name found",
			ActualOutput: "Error: storage account name is empty",
		})
		return commands
	}
	// Sanitize the storage account name for URL encoding
	storageAccountNameForUrl := url.QueryEscape(strings.TrimSpace(storageAccountName))

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Test anonymous access via HTTP request
	url := fmt.Sprintf("https://%s.blob.core.windows.net/?comp=list", storageAccountNameForUrl)

	resp, err := client.Get(url)

	command := fmt.Sprintf("curl -w \"\\n===== Status Code =====\\n%%{http_code}\\n\" \"%s\" --max-time 10", url)
	curlCommand := templates.Command{
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
	}

	commands = append(commands, curlCommand)

	return commands
}
