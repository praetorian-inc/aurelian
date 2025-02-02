package stages

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/internal/message"
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

			// Process each subscription
			for _, subscription := range config.Subscriptions {
				logger.Info("Processing subscription", slog.String("subscription", subscription))

				// Build ARG query for Function Apps
				query := `
					resources
					| where type =~ 'Microsoft.Web/sites'
					| where kind in~ ('functionapp', 'functionapp,linux', 'functionapp,windows')
					| extend 
						siteName = name,
						siteKind = kind,
						state = properties.state,
						hostingPlan = properties.serverFarmId
					| project
						id,
						name,
						resourceGroup,
						location,
						subscriptionId,
						siteKind,
						state,
						hostingPlan,
						properties=pack_all()
				`

				// Execute query and process results
				queryOpts := &helpers.ARGQueryOptions{
					Subscriptions: []string{subscription},
				}

				message.Info("Discovering Function Apps in subscription %s", subscription)

				err = argClient.ExecutePaginatedQuery(ctx, query, queryOpts, func(response *armresourcegraph.ClientResourcesResponse) error {
					if response == nil || response.Data == nil {
						return nil
					}

					rows, ok := response.Data.([]interface{})
					if !ok {
						logger.Error("Response data is not of expected type []interface{}")
						return fmt.Errorf("unexpected response data type")
					}

					logger.Info("Found potential Function Apps",
						slog.Int("count", len(rows)),
						slog.String("subscription", subscription))

					if len(rows) == 0 {
						logger.Debug("No Function Apps found in subscription",
							slog.String("subscription", subscription))
						return nil
					}

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
					continue
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
		message.Info("Beginning scan of Microsoft.Web/sites (Function Apps)")
		appsScanned := 0
		defer close(out)

		// Helper function to send to Nosey Parker
		sendNpInput := func(content string, contentType string, isBase64 bool, app *AzureFunctionAppDetail) {
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

		// Process each Function App
		for app := range in {
			appsScanned++
			logger.Info("Processing Function App",
				slog.String("name", app.Name),
				slog.String("resourceGroup", app.ResourceGroup))

			// Get Azure credentials
			cred, err := azidentity.NewDefaultAzureCredential(nil)
			if err != nil {
				logger.Error("Failed to get Azure credential",
					slog.String("error", err.Error()))
				continue
			}

			// Create Web Apps client
			webClient, err := armappservice.NewWebAppsClient(app.SubscriptionID, cred, nil)
			if err != nil {
				logger.Error("Failed to create web client",
					slog.String("error", err.Error()))
				continue
			}

			// 1. Application Settings
			appSettings, err := webClient.ListApplicationSettings(ctx, app.ResourceGroup, app.Name, nil)
			if err == nil && appSettings.Properties != nil {
				if settingsJson, err := json.Marshal(appSettings.Properties); err == nil {
					sendNpInput(string(settingsJson), "AppSettings", false, app)
				}
			}

			// 2. Connection Strings
			connStrings, err := webClient.ListConnectionStrings(ctx, app.ResourceGroup, app.Name, nil)
			if err == nil && connStrings.Properties != nil {
				if stringsJson, err := json.Marshal(connStrings.Properties); err == nil {
					sendNpInput(string(stringsJson), "ConnectionStrings", false, app)
				}
			}

			// 3. Function Keys and Host Keys
			// Get function keys
			funcKeys, err := webClient.ListFunctionKeys(ctx, app.ResourceGroup, app.Name, "", nil)
			if err == nil {
				if keysJson, err := json.Marshal(funcKeys); err == nil {
					sendNpInput(string(keysJson), "FunctionKeys", false, app)
				}
			}

			// Get host level keys
			hostKeys, err := webClient.ListHostKeys(ctx, app.ResourceGroup, app.Name, nil)
			if err == nil {
				if keysJson, err := json.Marshal(hostKeys); err == nil {
					sendNpInput(string(keysJson), "HostKeys", false, app)
				}
			}

			// 4. Source Control Details
			sourceControl, err := webClient.GetSourceControl(ctx, app.ResourceGroup, app.Name, nil)
			if err == nil && sourceControl.Properties != nil {
				if scJson, err := json.Marshal(sourceControl.Properties); err == nil {
					sendNpInput(string(scJson), "SourceControl", false, app)
				}

				// If source control is configured, check for additional secrets
				if sourceControl.Properties.RepoURL != nil {
					sendNpInput(*sourceControl.Properties.RepoURL, "SourceControlURL", false, app)
				}
			}

			// 5. Function Configuration and Triggers
			syncTriggers, err := webClient.SyncFunctionTriggers(ctx, app.ResourceGroup, app.Name, nil)
			if err == nil {
				if triggerJson, err := json.Marshal(syncTriggers); err == nil {
					sendNpInput(string(triggerJson), "FunctionTriggers", false, app)
				}
			}

			// 6. Deployment Slots
			slotsPager := webClient.NewListSlotsPager(app.ResourceGroup, app.Name, nil)
			for slotsPager.More() {
				slots, err := slotsPager.NextPage(ctx)
				if err == nil {
					for _, slot := range slots.Value {
						if slot.Name == nil {
							continue
						}

						// Get slot settings
						slotSettings, err := webClient.ListApplicationSettingsSlot(ctx, app.ResourceGroup, app.Name, *slot.Name, nil)
						if err == nil && slotSettings.Properties != nil {
							if settingsJson, err := json.Marshal(slotSettings.Properties); err == nil {
								sendNpInput(string(settingsJson),
									fmt.Sprintf("SlotSettings::%s", *slot.Name),
									false, app)
							}
						}

						// Get slot connection strings
						slotConnStrings, err := webClient.ListConnectionStringsSlot(ctx, app.ResourceGroup, app.Name, *slot.Name, nil)
						if err == nil && slotConnStrings.Properties != nil {
							if stringsJson, err := json.Marshal(slotConnStrings.Properties); err == nil {
								sendNpInput(string(stringsJson),
									fmt.Sprintf("SlotConnectionStrings::%s", *slot.Name),
									false, app)
							}
						}
					}
				}
			}

			// 7. Authentication Settings
			authSettings, err := webClient.GetAuthSettings(ctx, app.ResourceGroup, app.Name, nil)
			if err == nil && authSettings.Properties != nil {
				if authJson, err := json.Marshal(authSettings.Properties); err == nil {
					sendNpInput(string(authJson), "AuthSettings", false, app)
				}
			}

			// 8. Site Configuration (includes identity info and auth settings)
			siteConfig, err := webClient.GetConfiguration(ctx, app.ResourceGroup, app.Name, nil)
			if err == nil && siteConfig.Properties != nil {
				if configJson, err := json.Marshal(siteConfig.Properties); err == nil {
					sendNpInput(string(configJson), "SiteConfiguration", false, app)
				}
			}

			// 9. Diagnostic Settings
			diagSettings, err := webClient.GetDiagnosticLogsConfiguration(ctx, app.ResourceGroup, app.Name, nil)
			if err == nil && diagSettings.Properties != nil {
				if diagJson, err := json.Marshal(diagSettings.Properties); err == nil {
					sendNpInput(string(diagJson), "DiagnosticSettings", false, app)
				}
			}

			// 9. Get function content using Kudu API if SCM URI is available
			if app.Properties != nil {
				if scmURI, ok := app.Properties["scmUri"].(string); ok {
					if functionContent, err := getFunctionContent(scmURI, app.Name); err == nil {
						sendNpInput(functionContent, "FunctionContent", false, app)
					}
				}
			}
		}

		message.Info("Completed scanning Microsoft.Web/sites, %d function apps scanned", appsScanned)
	}()

	return out
}

// Helper function to skip binary and unwanted files
func shouldSkipFile(fileName string) bool {
	ext := strings.ToLower(filepath.Ext(fileName))
	skipExts := []string{
		".dll", ".exe", ".pdb", ".jpg", ".jpeg", ".png",
		".gif", ".ico", ".woff", ".woff2", ".ttf",
	}

	for _, skipExt := range skipExts {
		if ext == skipExt {
			return true
		}
	}

	return false
}

// Helper function to get function content using Kudu API
func getFunctionContent(kuduURL string, functionName string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Construct the Kudu API URL for the function content
	vfsURL := fmt.Sprintf("%s/api/vfs/site/wwwroot/%s/", kuduURL, functionName)

	req, err := http.NewRequestWithContext(ctx, "GET", vfsURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(content), nil
}
