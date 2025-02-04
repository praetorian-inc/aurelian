package stages

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AzureFunctionAppDetail contains all relevant information about an Azure Function App
type AzureFunctionAppDetail struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	ResourceGroup  string                 `json:"resourceGroup"`
	Location       string                 `json:"location"`
	SubscriptionID string                 `json:"subscriptionId"`
	Tags           map[string]*string     `json:"tags"`
	Properties     map[string]interface{} `json:"properties"`
}

// AzureListFunctionAppsStage uses Azure Resource Graph to efficiently list Function Apps across subscriptions
func AzureListFunctionAppsStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan *AzureFunctionAppDetail {
	logger := logs.NewStageLogger(ctx, opts, "AzureListFunctionAppsStage")
	out := make(chan *AzureFunctionAppDetail)

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

			logger.Info("Listing Function Apps across subscriptions")

			// Process each subscription
			for _, subscription := range config.Subscriptions {
				logger.Info("Processing subscription", slog.String("subscription", subscription))

				// Build ARG query for Function Apps
				query := `
					resources
					| where type =~ 'Microsoft.Web/sites'
					| where kind contains 'functionapp'
					| project id, name, resourceGroup, location, tags, properties=pack_all()
					`

				// Execute query and process results
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

					logger.Info("Processing Function App data",
						slog.Int("page_total_resource_count", len(rows)),
						slog.Int("page", page_no),
					)

					for _, row := range rows {
						item, ok := row.(map[string]interface{})
						if !ok {
							continue
						}

						appDetail := &AzureFunctionAppDetail{
							SubscriptionID: subscription,
						}

						// Extract basic fields
						if id, ok := item["id"].(string); ok {
							appDetail.ID = id
						}
						if name, ok := item["name"].(string); ok {
							appDetail.Name = name
						}
						if rg, ok := item["resourceGroup"].(string); ok {
							appDetail.ResourceGroup = rg
						}
						if location, ok := item["location"].(string); ok {
							appDetail.Location = location
						}

						// Extract tags
						appDetail.Tags = make(map[string]*string)
						if tagData, ok := item["tags"].(map[string]interface{}); ok {
							for k, v := range tagData {
								if v != nil {
									vStr := fmt.Sprintf("%v", v)
									appDetail.Tags[k] = &vStr
								}
							}
						}

						// Extract properties
						if properties, ok := item["properties"].(map[string]interface{}); ok {
							appDetail.Properties = properties
						} else {
							appDetail.Properties = make(map[string]interface{})
						}

						select {
						case out <- appDetail:
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

// Function App configuration settings
func AzureFunctionAppConfigStage(ctx context.Context, opts []*types.Option, in <-chan *AzureFunctionAppDetail) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "AzureFunctionAppConfigStage")
	out := make(chan types.NpInput)

	go func() {
		defer close(out)
		for app := range in {
			cred, err := azidentity.NewDefaultAzureCredential(nil)
			if err != nil {
				logger.Error("Failed to get Azure credential", slog.String("error", err.Error()))
				continue
			}

			logger.Debug("Processing Function App Configurations for secrets", slog.String("name", app.Name))

			webClient, err := armappservice.NewWebAppsClient(app.SubscriptionID, cred, nil)
			if err != nil {
				logger.Error("Failed to create web client", slog.String("error", err.Error()))
				continue
			}

			// Application Settings
			appSettings, err := webClient.ListApplicationSettings(ctx, app.ResourceGroup, app.Name, nil)
			if err != nil {
				logFunctionAppError(logger, "Failed to list application settings", err, app.Name)
			} else if len(appSettings.Properties) > 0 {
				if settingsJson, err := json.Marshal(appSettings.Properties); err == nil {
					select {
					case out <- types.NpInput{
						Content: string(settingsJson),
						Provenance: types.NpProvenance{
							Platform:     "azure",
							ResourceType: "Microsoft.Web/sites::AppSettings",
							ResourceID:   app.ID,
							Region:       app.Location,
							AccountID:    app.SubscriptionID,
						},
					}:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()
	return out
}

// Function App connection strings
func AzureFunctionAppConnectionsStage(ctx context.Context, opts []*types.Option, in <-chan *AzureFunctionAppDetail) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "AzureFunctionAppConnectionsStage")
	out := make(chan types.NpInput)

	go func() {
		defer close(out)
		for app := range in {
			cred, err := azidentity.NewDefaultAzureCredential(nil)
			if err != nil {
				logger.Error("Failed to get Azure credential", slog.String("error", err.Error()))
				continue
			}

			logger.Debug("Processing Function App Connection Strings for secrets", slog.String("name", app.Name))

			webClient, err := armappservice.NewWebAppsClient(app.SubscriptionID, cred, nil)
			if err != nil {
				logger.Error("Failed to create web client", slog.String("error", err.Error()))
				continue
			}

			// Connection Strings
			connStrings, err := webClient.ListConnectionStrings(ctx, app.ResourceGroup, app.Name, nil)
			if err != nil {
				logFunctionAppError(logger, "Failed to list connection strings", err, app.Name)
			} else if connStrings.Properties != nil {
				if stringsJson, err := json.Marshal(connStrings.Properties); err == nil {
					select {
					case out <- types.NpInput{
						Content: string(stringsJson),
						Provenance: types.NpProvenance{
							Platform:     "azure",
							ResourceType: "Microsoft.Web/sites::ConnectionStrings",
							ResourceID:   app.ID,
							Region:       app.Location,
							AccountID:    app.SubscriptionID,
						},
					}:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()
	return out
}

// Function App keys
func AzureFunctionAppKeysStage(ctx context.Context, opts []*types.Option, in <-chan *AzureFunctionAppDetail) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "AzureFunctionAppKeysStage")
	out := make(chan types.NpInput)

	go func() {
		defer close(out)
		for app := range in {
			cred, err := azidentity.NewDefaultAzureCredential(nil)
			if err != nil {
				logger.Error("Failed to get Azure credential", slog.String("error", err.Error()))
				continue
			}

			webClient, err := armappservice.NewWebAppsClient(app.SubscriptionID, cred, nil)
			if err != nil {
				logger.Error("Failed to create web client", slog.String("error", err.Error()))
				continue
			}

			// Get host keys (these are app-level keys)
			hostKeys, err := webClient.ListHostKeys(ctx, app.ResourceGroup, app.Name, nil)
			if err != nil {
				logFunctionAppError(logger, "Failed to list host keys", err, app.Name)
			} else {
				if keysJson, err := json.Marshal(hostKeys); err == nil {
					select {
					case out <- types.NpInput{
						Content: string(keysJson),
						Provenance: types.NpProvenance{
							Platform:     "azure",
							ResourceType: "Microsoft.Web/sites::HostKeys",
							ResourceID:   app.ID,
							Region:       app.Location,
							AccountID:    app.SubscriptionID,
						},
					}:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()
	return out
}

// Function App auth and source control settings
func AzureFunctionAppSettingsStage(ctx context.Context, opts []*types.Option, in <-chan *AzureFunctionAppDetail) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "AzureFunctionAppSettingsStage")
	out := make(chan types.NpInput)

	go func() {
		defer close(out)
		for app := range in {
			cred, err := azidentity.NewDefaultAzureCredential(nil)
			logger.Debug("Processing Function App Settings for secrets", slog.String("name", app.Name))
			if err != nil {
				logger.Error("Failed to get Azure credential", slog.String("error", err.Error()))
				continue
			}

			webClient, err := armappservice.NewWebAppsClient(app.SubscriptionID, cred, nil)
			if err != nil {
				logger.Error("Failed to create web client", slog.String("error", err.Error()))
				continue
			}

			// Auth Settings
			authSettings, err := webClient.GetAuthSettings(ctx, app.ResourceGroup, app.Name, nil)
			if err != nil {
				logFunctionAppError(logger, "Failed to get auth settings", err, app.Name)
			} else if authSettings.Properties != nil {
				if authJson, err := json.Marshal(authSettings.Properties); err == nil {
					select {
					case out <- types.NpInput{
						Content: string(authJson),
						Provenance: types.NpProvenance{
							Platform:     "azure",
							ResourceType: "Microsoft.Web/sites::AuthSettings",
							ResourceID:   app.ID,
							Region:       app.Location,
							AccountID:    app.SubscriptionID,
						},
					}:
					case <-ctx.Done():
						return
					}
				}
			}

			// Source Control
			sourceControl, err := webClient.GetSourceControl(ctx, app.ResourceGroup, app.Name, nil)
			if err != nil {
				logFunctionAppError(logger, "Failed to get source control settings", err, app.Name)
			} else if sourceControl.Properties != nil {
				if scJson, err := json.Marshal(sourceControl.Properties); err == nil {
					select {
					case out <- types.NpInput{
						Content: string(scJson),
						Provenance: types.NpProvenance{
							Platform:     "azure",
							ResourceType: "Microsoft.Web/sites::SourceControl",
							ResourceID:   app.ID,
							Region:       app.Location,
							AccountID:    app.SubscriptionID,
						},
					}:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()
	return out
}

// Function App Resource Tags
func AzureFunctionAppTagsStage(ctx context.Context, opts []*types.Option, in <-chan *AzureFunctionAppDetail) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "AzureFunctionAppTagsStage")
	out := make(chan types.NpInput)

	go func() {
		defer close(out)
		for app := range in {
			logger.Debug("Processing Function App Tags for secrets", slog.String("name", app.Name))
			if app.Tags != nil && len(app.Tags) > 0 {
				tagsJson, err := json.Marshal(app.Tags)
				if err == nil {
					select {
					case out <- types.NpInput{
						Content: string(tagsJson),
						Provenance: types.NpProvenance{
							Platform:     "azure",
							ResourceType: "Microsoft.Web/sites::Tags",
							ResourceID:   app.ID,
							Region:       app.Location,
							AccountID:    app.SubscriptionID,
						},
					}:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()
	return out
}

// Helper function for Function App error logging
func logFunctionAppError(logger *slog.Logger, msg string, err error, appName string) {
	if strings.Contains(err.Error(), "AuthorizationFailed") ||
		strings.Contains(err.Error(), "InvalidAuthenticationToken") ||
		strings.Contains(err.Error(), "403") {
		logger.Debug("Insufficient permissions",
			slog.String("function_app", appName),
			slog.String("error", err.Error()))
	} else {
		logger.Error(msg,
			slog.String("function_app", appName),
			slog.String("error", err.Error()))
	}
}
