package enrichers

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
)

func init() {
	plugin.RegisterAzureEnricher("storage_accounts_public_access", enrichStorageAccount)
}

func enrichStorageAccount(cfg plugin.AzureEnricherConfig, result *templates.ARGQueryResult) ([]plugin.AzureEnrichmentCommand, error) {
	storageAccountName := result.ResourceName
	if storageAccountName == "" {
		return nil, nil
	}

	storageAccountNameForURL := url.QueryEscape(strings.TrimSpace(storageAccountName))
	testURL := fmt.Sprintf("https://%s.blob.core.windows.net/?comp=list", storageAccountNameForURL)
	curlEquiv := fmt.Sprintf("curl -i '%s' --max-time 3", testURL)

	client := NewHTTPClient(3 * time.Second)
	cmd := HTTPProbe(client, testURL, curlEquiv,
		"Test anonymous access to storage account container listing",
		"anonymous access enabled = 404 | anonymous access disabled = 401/403 | public access disabled = 409",
	)

	return []plugin.AzureEnrichmentCommand{cmd}, nil
}
