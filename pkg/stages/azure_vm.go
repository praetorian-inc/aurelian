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
	Tags           map[string]*string     `json:"tags"`
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

				// Build ARG query for VMs - now including tags
				query := `
					resources
					| where type =~ 'Microsoft.Compute/virtualMachines'
					| extend resourceGroup = resourceGroup
					| extend osType = properties.storageProfile.osDisk.osType
					| extend osProfile = properties.osProfile
					| extend computerName = properties.osProfile.computerName
					| project id, name, resourceGroup, location, tags, properties
					| project id, name, resourceGroup, location, tags, properties
					`

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

					logger.Info("Processing VM data",
						slog.Int("page_total_resource_count", len(rows)),
						slog.Int("page", page_no),
					)

					for _, row := range rows {
						item, ok := row.(map[string]interface{})
						if !ok {
							continue
						}

						vmDetail := &AzureVMDetail{
							SubscriptionID: subscription,
						}

						// Extract basic fields
						if id, ok := item["id"].(string); ok {
							vmDetail.ID = id
						}
						if name, ok := item["name"].(string); ok {
							vmDetail.Name = name
						}
						if rg, ok := item["resourceGroup"].(string); ok {
							vmDetail.ResourceGroup = rg
						}
						if location, ok := item["location"].(string); ok {
							vmDetail.Location = location
						}

						// Extract tags
						if tags, ok := item["tags"].(map[string]interface{}); ok {
							vmDetail.Tags = make(map[string]*string)
							for k, v := range tags {
								if v != nil {
									vStr := fmt.Sprintf("%v", v)
									vmDetail.Tags[k] = &vStr
								}
							}
						}

						// Extract properties
						if properties, ok := item["properties"].(map[string]interface{}); ok {
							vmDetail.Properties = properties
						} else {
							vmDetail.Properties = make(map[string]interface{})
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

// AzureVMUserDataStage processes VM user and custom data
func AzureVMUserDataStage(ctx context.Context, opts []*types.Option, in <-chan *AzureVMDetail) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "AzureVMUserDataStage")
	out := make(chan types.NpInput)

	go func() {
		defer close(out)
		for vm := range in {
			cred, err := azidentity.NewDefaultAzureCredential(nil)
			if err != nil {
				logger.Error("Failed to get Azure credential", slog.String("error", err.Error()))
				continue
			}

			vmClient, err := armcompute.NewVirtualMachinesClient(vm.SubscriptionID, cred, nil)
			if err != nil {
				logger.Error("Failed to create VM client", slog.String("error", err.Error()))
				continue
			}

			// Get VM details including UserData
			userDataExpand := armcompute.InstanceViewTypesUserData
			vmDetails, err := vmClient.Get(ctx, vm.ResourceGroup, vm.Name, &armcompute.VirtualMachinesClientGetOptions{
				Expand: &userDataExpand,
			})
			if err != nil {
				logVMError(logger, "Failed to get VM details", err, vm.Name)
				continue
			}

			if vmDetails.Properties != nil {
				// Process UserData
				if vmDetails.Properties.UserData != nil {
					select {
					case out <- types.NpInput{
						ContentBase64: *vmDetails.Properties.UserData,
						Provenance: types.NpProvenance{
							Platform:     "azure",
							ResourceType: "Microsoft.Compute/virtualMachines::UserData",
							ResourceID:   vm.ID,
							Region:       vm.Location,
							AccountID:    vm.SubscriptionID,
						},
					}:
					case <-ctx.Done():
						return
					}
				}

				// Process OSProfile and CustomData
				if vmDetails.Properties.OSProfile != nil {
					if vmDetails.Properties.OSProfile.CustomData != nil {
						select {
						case out <- types.NpInput{
							ContentBase64: *vmDetails.Properties.OSProfile.CustomData,
							Provenance: types.NpProvenance{
								Platform:     "azure",
								ResourceType: "Microsoft.Compute/virtualMachines::CustomData",
								ResourceID:   vm.ID,
								Region:       vm.Location,
								AccountID:    vm.SubscriptionID,
							},
						}:
						case <-ctx.Done():
							return
						}
					}

					if osProfileJson, err := json.Marshal(vmDetails.Properties.OSProfile); err == nil {
						select {
						case out <- types.NpInput{
							Content: string(osProfileJson),
							Provenance: types.NpProvenance{
								Platform:     "azure",
								ResourceType: "Microsoft.Compute/virtualMachines::OSProfile",
								ResourceID:   vm.ID,
								Region:       vm.Location,
								AccountID:    vm.SubscriptionID,
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

// AzureVMExtensionsStage processes VM extensions
func AzureVMExtensionsStage(ctx context.Context, opts []*types.Option, in <-chan *AzureVMDetail) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "AzureVMExtensionsStage")
	out := make(chan types.NpInput)

	go func() {
		defer close(out)
		for vm := range in {
			logger.Debug("Processing Virtual Machine Extension for secrets", slog.String("name", vm.Name))
			cred, err := azidentity.NewDefaultAzureCredential(nil)
			if err != nil {
				logger.Error("Failed to get Azure credential", slog.String("error", err.Error()))
				continue
			}

			extensionsClient, err := armcompute.NewVirtualMachineExtensionsClient(vm.SubscriptionID, cred, nil)
			if err != nil {
				logger.Error("Failed to create extensions client", slog.String("error", err.Error()))
				continue
			}

			extensions, err := extensionsClient.List(ctx, vm.ResourceGroup, vm.Name, nil)
			if err != nil {
				logVMError(logger, "Failed to list extensions", err, vm.Name)
				continue
			}

			for _, ext := range extensions.Value {
				if ext.Properties == nil {
					continue
				}

				// Process extension settings
				if ext.Properties.Settings != nil {
					if settingsJson, err := json.Marshal(ext.Properties.Settings); err == nil {
						select {
						case out <- types.NpInput{
							Content: string(settingsJson),
							Provenance: types.NpProvenance{
								Platform:     "azure",
								ResourceType: "Microsoft.Compute/virtualMachines::Extension::Settings",
								ResourceID:   vm.ID,
								Region:       vm.Location,
								AccountID:    vm.SubscriptionID,
							},
						}:
						case <-ctx.Done():
							return
						}
					}
				}

				// Process Custom Script Extension outputs
				if ext.Properties.Type != nil && strings.Contains(strings.ToLower(*ext.Properties.Type), "customscript") {
					status, err := extensionsClient.Get(ctx, vm.ResourceGroup, vm.Name, *ext.Name, nil)
					if err == nil && status.Properties != nil && status.Properties.InstanceView != nil {
						for _, substatus := range status.Properties.InstanceView.Substatuses {
							if substatus.Message != nil {
								select {
								case out <- types.NpInput{
									Content: *substatus.Message,
									Provenance: types.NpProvenance{
										Platform:     "azure",
										ResourceType: "Microsoft.Compute/virtualMachines::Extension::CustomScript",
										ResourceID:   vm.ID,
										Region:       vm.Location,
										AccountID:    vm.SubscriptionID,
									},
								}:
								case <-ctx.Done():
									return
								}
							}
						}
					}
				}
			}
		}
	}()
	return out
}

// AzureVMDiskEncryptionStage processes VM disk encryption settings
func AzureVMDiskEncryptionStage(ctx context.Context, opts []*types.Option, in <-chan *AzureVMDetail) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "AzureVMDiskEncryptionStage")
	out := make(chan types.NpInput)

	go func() {
		defer close(out)
		for vm := range in {
			cred, err := azidentity.NewDefaultAzureCredential(nil)
			logger.Debug("Processing Virtual Machine Disk Encryption for secrets", slog.String("name", vm.Name))
			if err != nil {
				logger.Error("Failed to get Azure credential", slog.String("error", err.Error()))
				continue
			}

			vmClient, err := armcompute.NewVirtualMachinesClient(vm.SubscriptionID, cred, nil)
			if err != nil {
				logger.Error("Failed to create VM client", slog.String("error", err.Error()))
				continue
			}

			vmDetails, err := vmClient.Get(ctx, vm.ResourceGroup, vm.Name, nil)
			if err != nil {
				logVMError(logger, "Failed to get VM details", err, vm.Name)
				continue
			}

			if vmDetails.Properties != nil && vmDetails.Properties.StorageProfile != nil &&
				vmDetails.Properties.StorageProfile.OSDisk != nil &&
				vmDetails.Properties.StorageProfile.OSDisk.EncryptionSettings != nil {
				encSettings := vmDetails.Properties.StorageProfile.OSDisk.EncryptionSettings
				if encSettings.DiskEncryptionKey != nil || encSettings.KeyEncryptionKey != nil {
					if encSettingsJson, err := json.Marshal(encSettings); err == nil {
						select {
						case out <- types.NpInput{
							Content: string(encSettingsJson),
							Provenance: types.NpProvenance{
								Platform:     "azure",
								ResourceType: "Microsoft.Compute/virtualMachines::DiskEncryption",
								ResourceID:   vm.ID,
								Region:       vm.Location,
								AccountID:    vm.SubscriptionID,
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

// AzureVMTagsStage processes VM tags
func AzureVMTagsStage(ctx context.Context, opts []*types.Option, in <-chan *AzureVMDetail) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "AzureVMTagsStage")
	out := make(chan types.NpInput)

	go func() {
		defer close(out)
		for vm := range in {
			logger.Debug("Processing Virtual Machine Tags for secrets", slog.String("name", vm.Name))
			if vm.Tags != nil && len(vm.Tags) > 0 {
				tagsJson, err := json.Marshal(vm.Tags)
				if err == nil {
					select {
					case out <- types.NpInput{
						Content: string(tagsJson),
						Provenance: types.NpProvenance{
							Platform:     "azure",
							ResourceType: "Microsoft.Compute/virtualMachines::Tags",
							ResourceID:   vm.ID,
							Region:       vm.Location,
							AccountID:    vm.SubscriptionID,
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

// Helper function for VM error logging
func logVMError(logger *slog.Logger, msg string, err error, vmName string) {
	if strings.Contains(err.Error(), "AuthorizationFailed") ||
		strings.Contains(err.Error(), "InvalidAuthenticationToken") ||
		strings.Contains(err.Error(), "403") {
		logger.Error("Insufficient permissions", slog.String("vm", vmName))
	} else {
		logger.Error(msg, slog.String("error", err.Error()))
	}
}
