package stages

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AzureVMDetail contains all relevant information about an Azure VM
type AzureVMDetail struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	ResourceGroup  string                 `json:"resourceGroup"`
	Location       string                 `json:"location"`
	SubscriptionID string                 `json:"subscriptionId"`
	Properties     map[string]interface{} `json:"properties"`
}

// AzureListVMsStage uses Azure Resource Graph to efficiently list VMs across subscriptions
func AzureListVMsStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan *AzureVMDetail {
	logger := logs.NewStageLogger(ctx, opts, "AzureListVMsStage")
	out := make(chan *AzureVMDetail)

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

			logger.Info("Listing VMs across subscriptions")

			// Process each subscription
			for _, subscription := range config.Subscriptions {
				logger.Info("Processing subscription", slog.String("subscription", subscription))

				// Build ARG query for VMs
				query := `
					resources
					| where type =~ 'Microsoft.Compute/virtualMachines'
					| extend resourceGroup = resourceGroup
					| extend osType = properties.storageProfile.osDisk.osType
					| extend osProfile = properties.osProfile
					| extend computerName = properties.osProfile.computerName
					`

				// Set up ARG query options
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

					logger.Info("Processing VM data", slog.Int("count", len(rows)))

					for _, row := range rows {
						item, ok := row.(map[string]interface{})
						if !ok {
							continue
						}

						vmName, ok := item["name"].(string)
						if !ok {
							continue
						}

						resourceGroup, ok := item["resourceGroup"].(string)
						if !ok {
							continue
						}

						vmId, ok := item["id"].(string)
						if !ok {
							continue
						}

						vmLocation, ok := item["location"].(string)
						if !ok {
							continue
						}

						properties, ok := item["properties"].(map[string]interface{})
						if !ok {
							properties = make(map[string]interface{})
						}

						vmDetail := &AzureVMDetail{
							ID:             vmId,
							Name:           vmName,
							ResourceGroup:  resourceGroup,
							Location:       vmLocation,
							SubscriptionID: subscription,
							Properties:     properties,
						}

						select {
						case out <- vmDetail:
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

// AzureVMSecretsStage processes VMs and extracts potential secrets
func AzureVMSecretsStage(ctx context.Context, opts []*types.Option, in <-chan *AzureVMDetail) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "AzureVMSecretsStage")
	out := make(chan types.NpInput)

	go func() {
		defer close(out)

		for vm := range in {
			logger.Debug("Processing VM for secrets", slog.String("name", vm.Name))

			// Get Azure credentials for VM operations
			cred, err := azidentity.NewDefaultAzureCredential(nil)
			if err != nil {
				logger.Error("Failed to get Azure credential",
					slog.String("subscription", vm.SubscriptionID),
					slog.String("error", err.Error()))
				continue
			}

			// Create VM client
			vmClient, err := armcompute.NewVirtualMachinesClient(vm.SubscriptionID, cred, nil)
			if err != nil {
				logger.Error("Failed to create VM client",
					slog.String("subscription", vm.SubscriptionID),
					slog.String("error", err.Error()))
				continue
			}

			// Helper function to send NpInput
			sendNpInput := func(content string, contentType string, isBase64 bool) {
				input := types.NpInput{
					Provenance: types.NpProvenance{
						Platform:     "azure",
						ResourceType: "Microsoft.Compute/virtualMachines::" + contentType,
						ResourceID:   vm.ID,
						Region:       vm.Location,
						AccountID:    vm.SubscriptionID,
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

			// 1. Get VM details including UserData and CustomData
			userDataExpand := armcompute.InstanceViewTypesUserData
			vmDetails, err := vmClient.Get(ctx, vm.ResourceGroup, vm.Name, &armcompute.VirtualMachinesClientGetOptions{
				Expand: &userDataExpand,
			})
			if err != nil {
				logger.Error("Failed to get VM details",
					slog.String("vm", vm.Name),
					slog.String("error", err.Error()))
				continue
			}

			// Process VM details for secrets
			if vmDetails.Properties != nil {
				if vmDetails.Properties.UserData != nil {
					sendNpInput(*vmDetails.Properties.UserData, "UserData", true)
				}

				if vmDetails.Properties.OSProfile != nil {
					if vmDetails.Properties.OSProfile.CustomData != nil {
						sendNpInput(*vmDetails.Properties.OSProfile.CustomData, "CustomData", true)
					}
					if osProfileJson, err := json.Marshal(vmDetails.Properties.OSProfile); err == nil {
						sendNpInput(string(osProfileJson), "OSProfile", false)
					}
				}
			}

			// 2. Process VM Extensions
			extensionsClient, err := armcompute.NewVirtualMachineExtensionsClient(vm.SubscriptionID, cred, nil)
			if err == nil {
				extensions, err := extensionsClient.List(ctx, vm.ResourceGroup, vm.Name, nil)
				if err == nil {
					for _, ext := range extensions.Value {
						if ext.Properties == nil {
							continue
						}

						// Check extension settings
						if ext.Properties.Settings != nil {
							if settingsJson, err := json.Marshal(ext.Properties.Settings); err == nil {
								sendNpInput(string(settingsJson),
									fmt.Sprintf("Extension::%s::Settings", *ext.Properties.Type), false)
							}
						}

						// Process Custom Script Extension outputs
						if ext.Properties.Type != nil && strings.Contains(strings.ToLower(*ext.Properties.Type), "customscript") {
							status, err := extensionsClient.Get(ctx, vm.ResourceGroup, vm.Name, *ext.Name, nil)
							if err == nil && status.Properties != nil && status.Properties.InstanceView != nil {
								for _, substatus := range status.Properties.InstanceView.Substatuses {
									if substatus.Message != nil {
										sendNpInput(*substatus.Message,
											fmt.Sprintf("Extension::%s::Output", *ext.Properties.Type), false)
									}
								}
							}
						}
					}
				}
			}

			// 3. Check Disk Encryption Settings
			if vmDetails.Properties != nil && vmDetails.Properties.StorageProfile != nil &&
				vmDetails.Properties.StorageProfile.OSDisk != nil &&
				vmDetails.Properties.StorageProfile.OSDisk.EncryptionSettings != nil {
				encSettings := vmDetails.Properties.StorageProfile.OSDisk.EncryptionSettings
				if encSettings.DiskEncryptionKey != nil || encSettings.KeyEncryptionKey != nil {
					if encSettingsJson, err := json.Marshal(encSettings); err == nil {
						sendNpInput(string(encSettingsJson), "DiskEncryptionSettings", false)
					}
				}
			}

			// 4. Check Boot Diagnostics Storage
			if vmDetails.Properties != nil && vmDetails.Properties.DiagnosticsProfile != nil &&
				vmDetails.Properties.DiagnosticsProfile.BootDiagnostics != nil &&
				vmDetails.Properties.DiagnosticsProfile.BootDiagnostics.StorageURI != nil {
				storageURI := *vmDetails.Properties.DiagnosticsProfile.BootDiagnostics.StorageURI
				if strings.Contains(storageURI, ".blob.core.windows.net") {
					sendNpInput(storageURI, "BootDiagnostics::StorageURI", false)
				}
			}
		}
	}()

	return out
}
