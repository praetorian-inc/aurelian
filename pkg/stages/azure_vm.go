package stages

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AzureVMListResourcesStage lists all VMs in an Azure subscription
func AzureVMListResourcesStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan types.ResourceInfo {
	logger := logs.NewStageLogger(ctx, opts, "AzureVMListResourcesStage")
	out := make(chan types.ResourceInfo)

	go func() {
		defer close(out)

		for subscription := range in {
			// Get Azure credentials
			cred, err := azidentity.NewDefaultAzureCredential(nil)
			if err != nil {
				logger.Error("Failed to get Azure credential",
					slog.String("error", err.Error()))
				continue
			}

			// Create VM client
			client, err := armcompute.NewVirtualMachinesClient(subscription, cred, nil)
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to create VM client: %v", err))
				continue
			}

			// List all VMs
			pager := client.NewListAllPager(nil)

			// Get first page
			hasResources := false
			firstPage := true

			for pager.More() {
				result, err := pager.NextPage(ctx)
				// Check first page for auth errors
				if firstPage && err != nil {
					if strings.Contains(err.Error(), "AuthorizationFailed") {
						logger.Info("No access to subscription",
							slog.String("subscription", subscription))
						// Return a special "no access" resource
						out <- types.ResourceInfo{
							Subscription: subscription,
							Type:         "NO_ACCESS",
						}
						break
					}
					logger.Error("Failed to list VMs",
						slog.String("error", err.Error()))
					break
				}
				firstPage = false

				if err != nil {
					logger.Error(fmt.Sprintf("Failed to get page: %v", err))
					break
				}

				for _, vm := range result.Value {
					if vm.ID == nil || vm.Name == nil || vm.Type == nil || vm.Location == nil {
						logger.Error("VM missing required properties")
						continue
					}

					hasResources = true
					resourceInfo := types.ResourceInfo{
						ID:            *vm.ID,
						Name:          *vm.Name,
						Type:          *vm.Type,
						Location:      *vm.Location,
						ResourceGroup: helpers.ExtractResourceGroup(*vm.ID),
						Subscription:  subscription,
						Tags:          vm.Tags,
						Properties:    make(map[string]interface{}),
					}

					select {
					case out <- resourceInfo:
					case <-ctx.Done():
						return
					}
				}
			}

			if !hasResources {
				logger.Info(fmt.Sprintf("No resources found in subscription %s", subscription))
			}
		}
	}()

	return out
}

// AzureVMScanSecretsStage performs comprehensive secret scanning of Azure VMs
func AzureVMScanSecretsStage(ctx context.Context, opts []*types.Option, in <-chan types.ResourceInfo) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "AzureVMScanSecretsStage")
	out := make(chan types.NpInput)

	go func() {
		defer close(out)

		for resource := range in {
			// Skip resources marked as no access
			if resource.Type == "NO_ACCESS" {
				continue
			}

			// Get Azure credentials
			cred, err := azidentity.NewDefaultAzureCredential(nil)
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to get Azure credential: %v", err))
				continue
			}

			// Create VM client with subscription from resource
			vmClient, err := armcompute.NewVirtualMachinesClient(resource.Subscription, cred, nil)
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to create VM client: %v", err))
				continue
			}

			// Helper function to send NpInput
			sendNpInput := func(content string, contentType string, isBase64 bool) {
				input := types.NpInput{
					Provenance: types.NpProvenance{
						Platform:     "azure",
						ResourceType: resource.Type + "::" + contentType,
						ResourceID:   resource.ID,
						Region:       resource.Location,
						AccountID:    resource.Subscription,
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
			vm, err := vmClient.Get(ctx, resource.ResourceGroup, resource.Name, &armcompute.VirtualMachinesClientGetOptions{
				Expand: &userDataExpand,
			})
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to get VM details: %v", err))
				continue
			}

			// Check UserData and CustomData
			if vm.Properties != nil {
				if vm.Properties.UserData != nil {
					sendNpInput(*vm.Properties.UserData, "UserData", true)
				}

				if vm.Properties.OSProfile != nil {
					if vm.Properties.OSProfile.CustomData != nil {
						sendNpInput(*vm.Properties.OSProfile.CustomData, "CustomData", true)
					}
					if osProfileJson, err := json.Marshal(vm.Properties.OSProfile); err == nil {
						sendNpInput(string(osProfileJson), "OSProfile", false)
					}
				}
			}

			// 2. Check VM Extensions including Custom Script Extension
			extensionsClient, err := armcompute.NewVirtualMachineExtensionsClient(resource.Subscription, cred, nil)
			if err != nil {
				logger.Error("Failed to create extensions client")
				continue
			}

			extensions, err := extensionsClient.List(ctx, resource.ResourceGroup, resource.Name, nil)
			if err != nil {
				logger.Error("Failed to list extensions")
				continue
			}

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

				// Handle Custom Script Extension
				if ext.Properties.Type != nil && (strings.Contains(*ext.Properties.Type, "CustomScript") ||
					strings.Contains(*ext.Properties.Type, "customscript")) {

					status, err := extensionsClient.Get(ctx, resource.ResourceGroup, resource.Name, *ext.Name, nil)
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

			// 3. Check Disk Encryption Settings
			if vm.Properties.StorageProfile != nil && vm.Properties.StorageProfile.OSDisk != nil {
				if vm.Properties.StorageProfile.OSDisk.EncryptionSettings != nil {
					encSettings := vm.Properties.StorageProfile.OSDisk.EncryptionSettings
					if encSettings.DiskEncryptionKey != nil || encSettings.KeyEncryptionKey != nil {
						if encSettingsJson, err := json.Marshal(encSettings); err == nil {
							sendNpInput(string(encSettingsJson), "DiskEncryptionSettings", false)
						}
					}
				}
			}

			// 4. Check Boot Diagnostics
			if vm.Properties.DiagnosticsProfile != nil &&
				vm.Properties.DiagnosticsProfile.BootDiagnostics != nil &&
				vm.Properties.DiagnosticsProfile.BootDiagnostics.StorageURI != nil {

				storageURI := *vm.Properties.DiagnosticsProfile.BootDiagnostics.StorageURI
				if strings.Contains(storageURI, ".blob.core.windows.net") {
					sendNpInput(storageURI, "BootDiagnostics::StorageURI", false)
				}
			}

			// 5. Configuration Management Extensions
			configExtensions := map[string]string{
				"DSC":    "Microsoft.Powershell.DSC",
				"Chef":   "Chef.Bootstrap.WindowsAzure",
				"Puppet": "PuppetLabs.PuppetEnterprise",
			}

			// Already have extensions list from earlier
			for _, ext := range extensions.Value {
				if ext.Properties == nil || ext.Properties.Type == nil {
					continue
				}

				for configType, extensionType := range configExtensions {
					if strings.Contains(*ext.Properties.Type, extensionType) {
						if ext.Properties.Settings != nil {
							if settingsJson, err := json.Marshal(ext.Properties.Settings); err == nil {
								sendNpInput(string(settingsJson),
									fmt.Sprintf("ConfigManagement::%s::Settings", configType), false)
							}
						}

						status, err := extensionsClient.Get(ctx, resource.ResourceGroup, resource.Name, *ext.Name, nil)
						if err == nil && status.Properties != nil && status.Properties.InstanceView != nil {
							for _, substatus := range status.Properties.InstanceView.Substatuses {
								if substatus.Message != nil {
									sendNpInput(*substatus.Message,
										fmt.Sprintf("ConfigManagement::%s::Output", configType), false)
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
