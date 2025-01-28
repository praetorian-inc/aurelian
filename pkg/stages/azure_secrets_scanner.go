// Package stages provides pipeline components for processing cloud resources
package stages

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/modules"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// AzureResourceHandler defines the interface that all Azure resource handlers must implement
type AzureResourceHandler interface {
	// ListResources gets all resources of a specific type from a subscription
	ListResources(ctx context.Context, subscription string, cred *azidentity.DefaultAzureCredential) ([]types.ResourceInfo, error)

	// ExtractSecretContent extracts any potential secret content from a resource
	ExtractSecretContent(ctx context.Context, resource types.ResourceInfo, subscription string, cred *azidentity.DefaultAzureCredential) ([]types.NpInput, error)
}

// ResourceHandlerRegistry manages the collection of resource handlers
type ResourceHandlerRegistry struct {
	handlers map[string]AzureResourceHandler
	mu       sync.RWMutex
}

// NewResourceHandlerRegistry creates a new registry for resource handlers
func NewResourceHandlerRegistry() *ResourceHandlerRegistry {
	return &ResourceHandlerRegistry{
		handlers: make(map[string]AzureResourceHandler),
	}
}

// Register adds a handler for a specific resource type
func (r *ResourceHandlerRegistry) Register(resourceType string, handler AzureResourceHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers[resourceType] = handler
}

// GetHandler retrieves the handler for a specific resource type
func (r *ResourceHandlerRegistry) GetHandler(resourceType string) (AzureResourceHandler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	handler, exists := r.handlers[resourceType]
	return handler, exists
}

// VMResourceHandler implements AzureResourceHandler for Virtual Machines
type VMResourceHandler struct{}

// ListResources gets all VMs in a subscription
func (h *VMResourceHandler) ListResources(ctx context.Context, subscription string, cred *azidentity.DefaultAzureCredential) ([]types.ResourceInfo, error) {
	client, err := armcompute.NewVirtualMachinesClient(subscription, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create VM client: %v", err)
	}

	var resources []types.ResourceInfo
	pager := client.NewListAllPager(nil)

	for pager.More() {
		result, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get next page: %v", err)
		}

		for _, vm := range result.Value {
			resources = append(resources, types.ResourceInfo{
				ID:            *vm.ID,
				Name:          *vm.Name,
				Type:          *vm.Type,
				Location:      *vm.Location,
				ResourceGroup: helpers.ExtractResourceGroup(*vm.ID),
				Tags:          vm.Tags,
				Properties:    make(map[string]interface{}),
			})
		}
	}

	return resources, nil
}

func (h *VMResourceHandler) makeNpInput(resource types.ResourceInfo, subscription, content, suffix string, isBase64 bool) types.NpInput {
	input := types.NpInput{
		Provenance: types.NpProvenance{
			Platform:     string(modules.Azure),
			ResourceType: resource.Type + "::" + suffix,
			ResourceID:   resource.ID,
			Region:       resource.Location,
			AccountID:    subscription,
		},
	}

	if isBase64 {
		input.ContentBase64 = content
	} else {
		input.Content = content
	}

	return input
}

// ExtractSecretContent extracts potential secret content from a VM resource
func (h *VMResourceHandler) ExtractSecretContent(ctx context.Context, resource types.ResourceInfo, subscription string, cred *azidentity.DefaultAzureCredential) ([]types.NpInput, error) {
	var inputs []types.NpInput
	logger := logs.NewStageLogger(ctx, nil, "VMResourceHandler")

	// Create VM client
	vmClient, err := armcompute.NewVirtualMachinesClient(subscription, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create VM client: %v", err)
	}

	// 1. Get VM details including UserData and CustomData
	userDataExpand := armcompute.InstanceViewTypesUserData
	vm, err := vmClient.Get(ctx, resource.ResourceGroup, resource.Name, &armcompute.VirtualMachinesClientGetOptions{
		Expand: &userDataExpand,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get VM details: %v", err)
	}

	// Check UserData
	if vm.Properties.UserData != nil {
		inputs = append(inputs, h.makeNpInput(resource, subscription, *vm.Properties.UserData, "UserData", true))
	}

	// Check OSProfile and CustomData
	if vm.Properties != nil && vm.Properties.OSProfile != nil {
		if vm.Properties.OSProfile.CustomData != nil {
			inputs = append(inputs, h.makeNpInput(resource, subscription, *vm.Properties.OSProfile.CustomData, "CustomData", true))
		}

		osProfileJson, err := json.Marshal(vm.Properties.OSProfile)
		if err == nil {
			inputs = append(inputs, h.makeNpInput(resource, subscription, string(osProfileJson), "OSProfile", false))
		}
	}

	// 2. Check VM Extensions including Custom Script Extension
	extensionsClient, err := armcompute.NewVirtualMachineExtensionsClient(subscription, cred, nil)
	if err != nil {
		logger.Error("Failed to create extensions client", slog.String("error", err.Error()))
	} else {
		extensions, err := extensionsClient.List(ctx, resource.ResourceGroup, resource.Name, nil)
		if err != nil {
			logger.Error("Failed to list extensions", slog.String("error", err.Error()))
		} else {
			for _, ext := range extensions.Value {
				if ext.Properties == nil {
					continue
				}

				// Check extension settings
				if ext.Properties.Settings != nil {
					settingsJson, err := json.Marshal(ext.Properties.Settings)
					if err == nil {
						inputs = append(inputs, h.makeNpInput(resource, subscription, string(settingsJson),
							fmt.Sprintf("Extension::%s::Settings", *ext.Properties.Type), false))
					}
				}

				// Handle Custom Script Extension specifically
				if ext.Properties.Type != nil && (strings.Contains(*ext.Properties.Type, "CustomScript") ||
					strings.Contains(*ext.Properties.Type, "customscript")) {

					// Get extension status and output
					status, err := extensionsClient.Get(ctx, resource.ResourceGroup, resource.Name, *ext.Name, nil)
					if err == nil && status.Properties != nil && status.Properties.InstanceView != nil {
						// Check substatuses for script output
						for _, substatus := range status.Properties.InstanceView.Substatuses {
							if substatus.Message != nil {
								inputs = append(inputs, h.makeNpInput(resource, subscription, *substatus.Message,
									fmt.Sprintf("Extension::%s::Output", *ext.Properties.Type), false))
							}
						}
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
				encSettingsJson, err := json.Marshal(encSettings)
				if err == nil {
					inputs = append(inputs, h.makeNpInput(resource, subscription, string(encSettingsJson),
						"DiskEncryptionSettings", false))
				}
			}
		}
	}

	// 4. Check Boot Diagnostics
	if vm.Properties.DiagnosticsProfile != nil &&
		vm.Properties.DiagnosticsProfile.BootDiagnostics != nil &&
		vm.Properties.DiagnosticsProfile.BootDiagnostics.StorageURI != nil {

		// Get the storage account info from the URI
		storageURI := *vm.Properties.DiagnosticsProfile.BootDiagnostics.StorageURI

		// Parse storage URI to get account name and key
		// Note: This requires additional permissions to access the storage account
		if strings.Contains(storageURI, ".blob.core.windows.net") {
			// Extract diagnostic logs if possible
			// This would require additional storage client implementation
			inputs = append(inputs, h.makeNpInput(resource, subscription, storageURI,
				"BootDiagnostics::StorageURI", false))
		}
	}

	// 5. Configuration Management Extensions
	configExtensions := map[string]string{
		"DSC":    "Microsoft.Powershell.DSC",
		"Chef":   "Chef.Bootstrap.WindowsAzure",
		"Puppet": "PuppetLabs.PuppetEnterprise",
	}

	// Get extensions again for config management check
	extensions, err := extensionsClient.List(ctx, resource.ResourceGroup, resource.Name, nil)
	if err != nil {
		logger.Error("Failed to list extensions for config management check", slog.String("error", err.Error()))
		return inputs, nil
	}

	for _, ext := range extensions.Value {
		if ext.Properties == nil || ext.Properties.Type == nil {
			continue
		}

		for configType, extensionType := range configExtensions {
			if strings.Contains(*ext.Properties.Type, extensionType) {
				if ext.Properties.Settings != nil {
					settingsJson, err := json.Marshal(ext.Properties.Settings)
					if err == nil {
						inputs = append(inputs, h.makeNpInput(resource, subscription, string(settingsJson),
							fmt.Sprintf("ConfigManagement::%s::Settings", configType), false))
					}
				}

				// Get configuration scripts if available
				status, err := extensionsClient.Get(ctx, resource.ResourceGroup, resource.Name, *ext.Name, nil)
				if err == nil && status.Properties != nil && status.Properties.InstanceView != nil {
					for _, substatus := range status.Properties.InstanceView.Substatuses {
						if substatus.Message != nil {
							inputs = append(inputs, h.makeNpInput(resource, subscription, *substatus.Message,
								fmt.Sprintf("ConfigManagement::%s::Output", configType), false))
						}
					}
				}
			}
		}
	}

	return inputs, nil
}

// AzureGetTargetedResourcesStage gets specific Azure resources for secret scanning
func AzureGetTargetedResourcesStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "AzureGetTargetedResourcesStage")
	out := make(chan types.NpInput)
	workersCount, _ := strconv.Atoi(options.GetOptionByName("workers", opts).Value)

	// Initialize registry and register handlers
	registry := NewResourceHandlerRegistry()
	registry.Register("Microsoft.Compute/virtualMachines", &VMResourceHandler{})

	type resourceInfo struct {
		count   int
		subName string
		subID   string
	}

	// Add counter with mutex-protected map for per-resource-type counts
	resourceCounts := make(map[string]resourceInfo)
	var countMutex sync.Mutex

	go func() {
		defer close(out)
		var wg sync.WaitGroup
		subscriptionChan := make(chan string)

		for i := 0; i < workersCount; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for subscription := range subscriptionChan {
					// reauthenticate to refresh credentials as this might be a long-running process
					cred, err := azidentity.NewDefaultAzureCredential(nil)
					if err != nil {
						logger.Error("Failed to get Azure credential", slog.String("error", err.Error()))
						continue
					}

					// Get subscription details first
					subDetails, err := helpers.GetSubscriptionDetails(ctx, cred, subscription)
					if err != nil {
						logger.Error("Failed to get subscription details", slog.String("error", err.Error()))
						continue
					}

					resourceType := options.GetOptionByName("resource-types", opts).Value
					handler, exists := registry.GetHandler(resourceType)
					if !exists {
						logger.Error("No handler found for resource type", slog.String("type", resourceType))
						continue
					}

					resources, err := handler.ListResources(ctx, subscription, cred)
					if err != nil {
						logger.Error("Failed to list resources",
							slog.String("type", resourceType),
							slog.String("error", err.Error()))
						continue
					}

					// Update count for this resource type
					countMutex.Lock()
					resourceCounts[resourceType] = resourceInfo{
						count:   len(resources),
						subName: *subDetails.DisplayName,
						subID:   subscription,
					}
					countMutex.Unlock()

					// For each resource, extract secrets using the handler
					for _, resource := range resources {
						secrets, err := handler.ExtractSecretContent(ctx, resource, subscription, cred)
						if err != nil {
							logger.Error("Failed to extract secrets",
								slog.String("resource", resource.ID),
								slog.String("error", err.Error()))
							continue
						}

						// Send each secret to the output channel
						for _, secret := range secrets {
							select {
							case out <- secret:
							case <-ctx.Done():
								return
							}
						}
					}
				}
			}()
		}

		for subscription := range in {
			subscriptionChan <- subscription
		}
		close(subscriptionChan)
		wg.Wait()

		// Log counts for each resource type at warn level
		for resourceType, info := range resourceCounts {
			message.Info("Completed scanning %s resources in subscription %s (%s): %d scanned",
				resourceType,
				info.subName,
				info.subID,
				info.count)
		}
	}()

	return out
}
