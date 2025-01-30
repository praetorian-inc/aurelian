package stages

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

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
					| project
						id,
						name,
						resourceGroup,
						location,
						subscriptionId,
						properties=pack_all()
					`

				// Execute query and process results
				queryOpts := &helpers.ARGQueryOptions{
					Subscriptions: []string{subscription},
				}

				err = argClient.ExecutePaginatedQuery(ctx, query, queryOpts, func(response *armresourcegraph.ClientResourcesResponse) error {
					if response == nil || response.Data == nil {
						return nil
					}

					rows, ok := response.Data.([]interface{})
					if !ok {
						return fmt.Errorf("unexpected response data type")
					}

					logger.Info("Processing Function App data", slog.Int("count", len(rows)))

					for _, row := range rows {
						item, ok := row.(map[string]interface{})
						if !ok {
							continue
						}

						// Extract required fields
						appDetail := &AzureFunctionAppDetail{
							SubscriptionID: subscription,
						}

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

// AzureFunctionAppSecretsStage processes Function Apps and extracts potential secrets
func AzureFunctionAppSecretsStage(ctx context.Context, opts []*types.Option, in <-chan *AzureFunctionAppDetail) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "AzureFunctionAppSecretsStage")
	out := make(chan types.NpInput)

	go func() {
		defer close(out)

		for app := range in {
			logger.Debug("Processing Function App for secrets", slog.String("name", app.Name))

			// Get Azure credentials
			cred, err := azidentity.NewDefaultAzureCredential(nil)
			if err != nil {
				logger.Error("Failed to get Azure credential",
					slog.String("subscription", app.SubscriptionID),
					slog.String("error", err.Error()))
				continue
			}

			// Create Web Apps client
			webClient, err := armappservice.NewWebAppsClient(app.SubscriptionID, cred, nil)
			if err != nil {
				logger.Error("Failed to create web client",
					slog.String("subscription", app.SubscriptionID),
					slog.String("error", err.Error()))
				continue
			}

			// Helper function to send NpInput
			sendNpInput := func(content string, contentType string, isBase64 bool) {
				input := types.NpInput{
					Provenance: types.NpProvenance{
						Platform:     "azure",
						ResourceType: "Microsoft.Web/sites::functionapp::" + contentType,
						ResourceID:   app.ID,
						Region:       app.Location,
						AccountID:    app.SubscriptionID,
					},
				}
				if isBase64 {
					input.ContentBase64 = content
				} else {
					input.Content = content
				}
				select {
				case out <- input:
				case <-ctx.Done():
					return
				}
			}

			// 1. Application Settings
			appSettings, err := webClient.ListApplicationSettings(ctx, app.ResourceGroup, app.Name, nil)
			if err == nil && len(appSettings.Properties) > 0 {
				if settingsJson, err := json.Marshal(appSettings.Properties); err == nil {
					sendNpInput(string(settingsJson), "AppSettings", false)
				}
			}

			// 2. Connection Strings
			connStrings, err := webClient.ListConnectionStrings(ctx, app.ResourceGroup, app.Name, nil)
			if err == nil && connStrings.Properties != nil {
				if stringsJson, err := json.Marshal(connStrings.Properties); err == nil {
					sendNpInput(string(stringsJson), "ConnectionStrings", false)
				}
			}

			// 3. Function Keys
			funcKeys, err := webClient.ListFunctionKeys(ctx, app.ResourceGroup, app.Name, "", nil)
			if err == nil {
				if keysJson, err := json.Marshal(funcKeys); err == nil {
					sendNpInput(string(keysJson), "FunctionKeys", false)
				}
			}

			// 4. Host Keys
			hostKeys, err := webClient.ListHostKeys(ctx, app.ResourceGroup, app.Name, nil)
			if err == nil {
				if keysJson, err := json.Marshal(hostKeys); err == nil {
					sendNpInput(string(keysJson), "HostKeys", false)
				}
			}

			// 5. Source Control Details
			sourceControl, err := webClient.GetSourceControl(ctx, app.ResourceGroup, app.Name, nil)
			if err == nil && sourceControl.Properties != nil {
				if scJson, err := json.Marshal(sourceControl.Properties); err == nil {
					sendNpInput(string(scJson), "SourceControl", false)
				}
			}

			// 6. Configuration (includes identity info)
			siteConfig, err := webClient.GetConfiguration(ctx, app.ResourceGroup, app.Name, nil)
			if err == nil && siteConfig.Properties != nil {
				if configJson, err := json.Marshal(siteConfig.Properties); err == nil {
					sendNpInput(string(configJson), "Configuration", false)
				}
			}
		}
	}()

	return out
}
