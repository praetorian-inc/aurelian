package stages

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/automation/armautomation"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AutomationAccountDetail contains metadata about an automation account
type AutomationAccountDetail struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	ResourceGroup  string                 `json:"resourceGroup"`
	Location       string                 `json:"location"`
	SubscriptionID string                 `json:"subscriptionId"`
	Tags           map[string]*string     `json:"tags"`
	Properties     map[string]interface{} `json:"properties"`
}

// AzureListAutomationAccountsStage lists all automation accounts using Azure Resource Graph
func AzureListAutomationAccountsStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan *AutomationAccountDetail {
	logger := logs.NewStageLogger(ctx, opts, "AzureListAutomationAccountsStage")
	out := make(chan *AutomationAccountDetail)

	go func() {
		defer close(out)

		// Initialize ARG client
		argClient, err := helpers.NewARGClient(ctx)
		if err != nil {
			logger.Error("Failed to create ARG client", slog.String("error", err.Error()))
			return
		}

		for configStr := range in {
			var config helpers.ScanConfig
			if err := json.Unmarshal([]byte(configStr), &config); err != nil {
				logger.Error("Failed to parse config", slog.String("error", err.Error()))
				continue
			}

			logger.Info("Listing Automation Accounts across subscriptions")

			// Process each subscription
			for _, subscription := range config.Subscriptions {
				logger.Info("Processing subscription", slog.String("subscription", subscription))

				// Build ARG query for Automation Accounts
				query := `
					    resources
    					| where type =~ 'Microsoft.Automation/automationAccounts'
    					| extend resourceGroup = resourceGroup
    					| extend properties = properties
    					| project id, name, resourceGroup, location, tags, properties
					`

				// Execute query with pagination support
				queryOpts := &helpers.ARGQueryOptions{
					Subscriptions: []string{subscription},
				}

				page_no := 0

				err = argClient.ExecutePaginatedQuery(ctx, query, queryOpts, func(response *armresourcegraph.ClientResourcesResponse) error {
					if response == nil || response.Data == nil {
						return nil
					}

					rows, ok := response.Data.([]interface{})
					if !ok {
						return fmt.Errorf("unexpected response data type")
					}

					page_no++

					logger.Info("Processing Automation Account data",
						slog.Int("page_total_resource_count", len(rows)),
						slog.Int("page", page_no),
					)

					for _, row := range rows {
						item, ok := row.(map[string]interface{})
						if !ok {
							continue
						}

						detail := &AutomationAccountDetail{
							SubscriptionID: subscription,
						}

						// Extract basic fields
						if id, ok := item["id"].(string); ok {
							detail.ID = id
						}
						if name, ok := item["name"].(string); ok {
							detail.Name = name
						}
						if rg, ok := item["resourceGroup"].(string); ok {
							detail.ResourceGroup = rg
						}
						if location, ok := item["location"].(string); ok {
							detail.Location = location
						}

						// Extract tags
						detail.Tags = make(map[string]*string)
						if tagData, ok := item["tags"].(map[string]interface{}); ok {
							for k, v := range tagData {
								if v != nil {
									vStr := fmt.Sprintf("%v", v)
									detail.Tags[k] = &vStr
								}
							}
						}

						// Extract properties
						if properties, ok := item["properties"].(map[string]interface{}); ok {
							detail.Properties = properties
						} else {
							detail.Properties = make(map[string]interface{})
						}

						select {
						case out <- detail:
						case <-ctx.Done():
							return nil
						}
					}
					return nil
				})

				if err != nil {
					logger.Error("Failed to execute ARG query",
						slog.String("subscription", subscription),
						slog.String("error", err.Error()))
				}
			}
		}
	}()

	return out
}

// AzureAutomationAccountSecretsStage scans automation accounts for potential secrets
func AzureAutomationAccountSecretsStage(ctx context.Context, opts []*types.Option, in <-chan *AutomationAccountDetail) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "AzureAutomationAccountSecretsStage")
	out := make(chan types.NpInput)

	go func() {
		message.Info("Began scanning Microsoft.Automation/automationAccounts")
		defer close(out)

		for account := range in {
			cred, err := azidentity.NewDefaultAzureCredential(nil)
			if err != nil {
				logger.Error("Failed to get Azure credential", slog.String("error", err.Error()))
				continue
			}

			// Function to send content to NP
			sendToNP := func(content string, contentType string, isBase64 bool) {
				input := types.NpInput{
					Provenance: types.NpProvenance{
						Platform:     "azure",
						ResourceType: "Microsoft.Automation/automationAccounts::" + contentType,
						ResourceID:   account.ID,
						Region:       account.Location,
						AccountID:    account.SubscriptionID,
					},
				}
				if isBase64 {
					input.ContentBase64 = content
				} else {
					input.Content = content
				}

				logger.Debug("Sending data to NP:",
					slog.String("subscription", account.SubscriptionID),
					slog.String("automation-account", account.ID),
					slog.String("content", content))

				select {
				case out <- input:
				case <-ctx.Done():
				}
			}

			// Process account tags
			if account.Tags != nil {
				if tagsJson, err := json.Marshal(account.Tags); err == nil {
					sendToNP(string(tagsJson), "Tags", false)
				}
			}

			// Process runbooks
			processRunbooks(ctx, logger, account, cred, sendToNP)

			// Process variables
			processVariables(ctx, logger, account, cred, sendToNP)
		}
	}()
	return out
}

func processRunbooks(ctx context.Context, logger *slog.Logger, account *AutomationAccountDetail, cred *azidentity.DefaultAzureCredential, sendToNP func(string, string, bool)) {
	runbookClient, err := armautomation.NewRunbookClient(account.SubscriptionID, cred, nil)
	if err != nil {
		logger.Error("Failed to create runbook client", slog.String("error", err.Error()))
		return
	}

	pager := runbookClient.NewListByAutomationAccountPager(account.ResourceGroup, account.Name, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			logError(logger, "Failed to list runbooks", err, account.Name)
			break
		}

		for _, runbook := range page.Value {
			if runbook.Name == nil {
				continue
			}

			contentURL := fmt.Sprintf("https://management.azure.com%s/%scontent?api-version=2018-06-30",
				*runbook.ID,
				getDraftPrefix(*runbook.Properties.State))

			content := getRunbookContent(ctx, logger, cred, contentURL, *runbook.Name)
			if content != "" {
				sendToNP(content, "Runbook::"+*runbook.Name, false)
			}
		}
	}
}

func processVariables(ctx context.Context, logger *slog.Logger, account *AutomationAccountDetail, cred *azidentity.DefaultAzureCredential, sendToNP func(string, string, bool)) {
	variableClient, err := armautomation.NewVariableClient(account.SubscriptionID, cred, nil)
	if err != nil {
		logger.Error("Failed to create variable client", slog.String("error", err.Error()))
		return
	}

	pager := variableClient.NewListByAutomationAccountPager(account.ResourceGroup, account.Name, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			logError(logger, "Failed to list variables", err, account.Name)
			break
		}

		for _, variable := range page.Value {
			if variable.Properties == nil || variable.Properties.IsEncrypted == nil || *variable.Properties.IsEncrypted {
				continue
			}

			if varJson, err := json.Marshal(map[string]interface{}{
				"name":        variable.Name,
				"description": variable.Properties.Description,
				"value":       variable.Properties.Value,
			}); err == nil {
				sendToNP(string(varJson), "Variable::"+*variable.Name, false)
			}
		}
	}
}

func getDraftPrefix(state armautomation.RunbookState) string {
	if state == armautomation.RunbookStateNew {
		return "draft/"
	}
	return ""
}

func getRunbookContent(ctx context.Context, logger *slog.Logger, cred *azidentity.DefaultAzureCredential, url string, name string) string {
	resp, err := helpers.MakeAzureRestRequest(ctx, http.MethodGet, url, cred)
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	defer resp.Body.Close()

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	if resp.Header.Get("Content-Type") == "application/octet-stream" {
		if decoded, err := base64.StdEncoding.DecodeString(string(content)); err == nil {
			return string(decoded)
		}
		if decoded, err := base64.URLEncoding.DecodeString(string(content)); err == nil {
			return string(decoded)
		}
	}

	return string(content)
}

func logError(logger *slog.Logger, msg string, err error, resourceName string) {
	if strings.Contains(err.Error(), "AuthorizationFailed") ||
		strings.Contains(err.Error(), "InvalidAuthenticationToken") ||
		strings.Contains(err.Error(), "403") {
		logger.Debug("Insufficient permissions", slog.String("resource", resourceName))
	} else {
		logger.Error(msg, slog.String("error", err.Error()))
	}
}
