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

func AutomationAccountRunbooksStage(ctx context.Context, opts []*types.Option, in <-chan *AutomationAccountDetail) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "AutomationAccountRunbooksStage")
	out := make(chan types.NpInput)

	go func() {
		defer close(out)

		for account := range in {
			logger.Debug("Processing Automation Account Runbooks for secrets", slog.String("name", account.Name))
			cred, err := azidentity.NewDefaultAzureCredential(nil)
			if err != nil {
				logger.Error("Failed to get Azure credential", slog.String("error", err.Error()))
				continue
			}

			runbookClient, err := armautomation.NewRunbookClient(account.SubscriptionID, cred, nil)
			if err != nil {
				logger.Error("Failed to create runbook client", slog.String("error", err.Error()))
				continue
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
						select {
						case out <- types.NpInput{
							Content: content,
							Provenance: types.NpProvenance{
								Platform:     "azure",
								ResourceType: "Microsoft.Automation/automationAccounts::Runbook",
								ResourceID:   account.ID,
								Region:       account.Location,
								AccountID:    account.SubscriptionID,
							},
						}:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}
	}()
	return out
}

// AutomationAccountVariablesStage processes variables of an automation account
func AutomationAccountVariablesStage(ctx context.Context, opts []*types.Option, in <-chan *AutomationAccountDetail) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "AutomationAccountVariablesStage")
	out := make(chan types.NpInput)

	go func() {
		defer close(out)

		for account := range in {
			cred, err := azidentity.NewDefaultAzureCredential(nil)
			logger.Debug("Processing Automation Account Variables for secrets", slog.String("name", account.Name))
			if err != nil {
				logger.Error("Failed to get Azure credential", slog.String("error", err.Error()))
				continue
			}

			variableClient, err := armautomation.NewVariableClient(account.SubscriptionID, cred, nil)
			if err != nil {
				logger.Error("Failed to create variable client", slog.String("error", err.Error()))
				continue
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
						select {
						case out <- types.NpInput{
							Content: string(varJson),
							Provenance: types.NpProvenance{
								Platform:     "azure",
								ResourceType: "Microsoft.Automation/automationAccounts::Variable",
								ResourceID:   account.ID,
								Region:       account.Location,
								AccountID:    account.SubscriptionID,
							},
						}:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}
	}()
	return out
}

// AutomationAccountJobsStage processes jobs of an automation account
func AutomationAccountJobsStage(ctx context.Context, opts []*types.Option, in <-chan *AutomationAccountDetail) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "AutomationAccountJobsStage")
	out := make(chan types.NpInput)

	go func() {
		defer close(out)

		for account := range in {
			cred, err := azidentity.NewDefaultAzureCredential(nil)
			logger.Debug("Processing Automation Account Jobs for secrets", slog.String("name", account.Name))
			if err != nil {
				logger.Error("Failed to get Azure credential", slog.String("error", err.Error()))
				continue
			}

			jobClient, err := armautomation.NewJobClient(account.SubscriptionID, cred, nil)
			if err != nil {
				logger.Error("Failed to create job client", slog.String("error", err.Error()))
				continue
			}

			pager := jobClient.NewListByAutomationAccountPager(account.ResourceGroup, account.Name, nil)
			for pager.More() {
				page, err := pager.NextPage(ctx)
				if err != nil {
					logError(logger, "Failed to list jobs", err, account.Name)
					break
				}

				for _, job := range page.Value {
					if job.Name == nil || job.Properties == nil {
						continue
					}

					// Send job properties
					if jobPropsJson, err := json.Marshal(job.Properties); err == nil {
						select {
						case out <- types.NpInput{
							Content: string(jobPropsJson),
							Provenance: types.NpProvenance{
								Platform:     "azure",
								ResourceType: "Microsoft.Automation/automationAccounts::Job::Properties",
								ResourceID:   account.ID,
								Region:       account.Location,
								AccountID:    account.SubscriptionID,
							},
						}:
						case <-ctx.Done():
							return
						}
					}

					// Get job output
					output, err := jobClient.GetOutput(ctx, account.ResourceGroup, account.Name, *job.Name, nil)
					if err != nil {
						logError(logger, "Failed to get job output", err, *job.Name)
					} else if output.Value != nil {
						select {
						case out <- types.NpInput{
							Content: *output.Value,
							Provenance: types.NpProvenance{
								Platform:     "azure",
								ResourceType: "Microsoft.Automation/automationAccounts::Job::Output",
								ResourceID:   account.ID,
								Region:       account.Location,
								AccountID:    account.SubscriptionID,
							},
						}:
						case <-ctx.Done():
							return
						}
					}

					// Get job streams (logs)
					streamClient, err := armautomation.NewJobStreamClient(account.SubscriptionID, cred, nil)
					if err != nil {
						logger.Error("Failed to create stream client", slog.String("error", err.Error()))
						continue
					}

					streamPager := streamClient.NewListByJobPager(account.ResourceGroup, account.Name, *job.Name, nil)
					var combinedLogs strings.Builder
					for streamPager.More() {
						streamPage, err := streamPager.NextPage(ctx)
						if err != nil {
							logError(logger, "Failed to list job streams", err, *job.Name)
							break
						}

						for _, stream := range streamPage.Value {
							if stream.Properties != nil && stream.Properties.Summary != nil {
								combinedLogs.WriteString(*stream.Properties.Summary + "\n")
							}
						}
					}

					if combinedLogs.Len() > 0 {
						select {
						case out <- types.NpInput{
							Content: combinedLogs.String(),
							Provenance: types.NpProvenance{
								Platform:     "azure",
								ResourceType: "Microsoft.Automation/automationAccounts::Job::Stream",
								ResourceID:   account.ID,
								Region:       account.Location,
								AccountID:    account.SubscriptionID,
							},
						}:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}
	}()
	return out
}

// Helper functions preserved from original code
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
