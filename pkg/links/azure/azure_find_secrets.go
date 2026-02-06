package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/links/azure/base"
	"github.com/praetorian-inc/aurelian/pkg/links/options"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/outputters"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// AzureFindSecretsLink processes Azure resources to find secrets using NoseyParker
type AzureFindSecretsLink struct {
	*base.NativeAzureLink
}

func NewAzureFindSecretsLink(args map[string]any) *AzureFindSecretsLink {
	return &AzureFindSecretsLink{
		NativeAzureLink: base.NewNativeAzureLink("azure-find-secrets", args),
	}
}

func (l *AzureFindSecretsLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		options.AzureSubscription(),
		options.AzureResourceSecretsTypes(),
		options.AzureWorkerCount(),
	}
}

func (l *AzureFindSecretsLink) SupportedResourceTypes() []string {
	return []string{
		"Microsoft.Compute/virtualMachines",
		"Microsoft.Compute/virtualMachines/userData",
		"Microsoft.Compute/virtualMachines/extensions",
		"Microsoft.Compute/virtualMachines/diskEncryption",
		"Microsoft.Compute/virtualMachines/tags",
		"Microsoft.Web/sites",
		"Microsoft.Web/sites/configuration",
		"Microsoft.Web/sites/connectionStrings",
		"Microsoft.Web/sites/keys",
		"Microsoft.Web/sites/settings",
		"Microsoft.Web/sites/tags",
		"Microsoft.Automation/automationAccounts/runbooks",
		"Microsoft.Automation/automationAccounts/variables",
		"Microsoft.Automation/automationAccounts/jobs",
	}
}

func (l *AzureFindSecretsLink) Process(ctx context.Context, input any) ([]any, error) {
	l.Logger().Debug("AzureFindSecretsLink received input", "input_type", fmt.Sprintf("%T", input))

	// Handle NamedOutputData wrapper from ARG template query
	var resource *output.CloudResource
	if namedData, ok := input.(outputters.NamedOutputData); ok {
		l.Logger().Debug("Processing NamedOutputData", "data_type", fmt.Sprintf("%T", namedData.Data))
		// Extract the actual data from the NamedOutputData
		if cloudResource, ok := namedData.Data.(*output.CloudResource); ok {
			resource = cloudResource
		} else if cloudResourceValue, ok := namedData.Data.(output.CloudResource); ok {
			resource = &cloudResourceValue
		} else {
			return nil, fmt.Errorf("expected CloudResource in NamedOutputData, got %T", namedData.Data)
		}
	} else if cloudResource, ok := input.(*output.CloudResource); ok {
		resource = cloudResource
	} else if cloudResourceValue, ok := input.(output.CloudResource); ok {
		resource = &cloudResourceValue
	} else {
		return nil, fmt.Errorf("expected CloudResource or NamedOutputData, got %T", input)
	}

	l.Logger().Debug("Processing Azure resource for secrets",
		"resource_type", resource.ResourceType,
		"resource_id", resource.ResourceID,
		"template_id", resource.Properties["templateID"])

	switch string(resource.ResourceType) {
	case "Microsoft.Compute/virtualMachines/userData":
		l.Logger().Debug("Processing VM userData", "vm_id", resource.ResourceID)
		if err := l.processVMUserData(ctx, resource); err != nil {
			return nil, err
		}
	case "Microsoft.Compute/virtualMachines/extensions":
		if err := l.processVMExtensions(ctx, resource); err != nil {
			return nil, err
		}
	case "Microsoft.Web/sites/configuration":
		if err := l.processFunctionAppConfig(ctx, resource); err != nil {
			return nil, err
		}
	case "Microsoft.Web/sites/connectionStrings":
		if err := l.processFunctionAppConnections(ctx, resource); err != nil {
			return nil, err
		}
	case "Microsoft.Web/sites/keys":
		if err := l.processFunctionAppKeys(ctx, resource); err != nil {
			return nil, err
		}
	case "microsoft.compute/virtualmachines", "Microsoft.Compute/virtualMachines":
		// Handle top-level VM resources from ARG templates - check userData
		l.Logger().Debug("Processing top-level VM resource for userData", "vm_id", resource.ResourceID)
		err := l.processVMUserData(ctx, resource)
		if err != nil {
			l.Logger().Debug("Failed to process VM user data, skipping", "vm_id", resource.ResourceID, "error", err.Error())
			return l.Outputs(), nil // Don't fail the whole chain
		}
		l.Logger().Debug("Successfully processed VM", "vm_id", resource.ResourceID)
	case "microsoft.web/sites", "Microsoft.Web/sites":
		// Handle top-level web app resources from ARG templates - check configuration
		l.Logger().Debug("Processing top-level Web App resource for configuration", "webapp_id", resource.ResourceID)
		// Try to process as function app, but don't fail if resource ID parsing fails
		err := l.processFunctionAppConfig(ctx, resource)
		if err != nil {
			l.Logger().Debug("Failed to process as function app, skipping", "webapp_id", resource.ResourceID, "error", err.Error())
			return l.Outputs(), nil // Don't fail the whole chain
		}
	case "microsoft.automation/automationaccounts", "Microsoft.Automation/automationAccounts":
		// Handle top-level automation account resources - check variables and runbooks
		l.Logger().Debug("Processing top-level Automation Account resource", "automation_id", resource.ResourceID)
		err := l.processAutomationAccount(ctx, resource)
		if err != nil {
			l.Logger().Debug("Failed to process automation account, skipping", "automation_id", resource.ResourceID, "error", err.Error())
			return l.Outputs(), nil // Don't fail the whole chain
		}
	default:
		l.Logger().Debug("Unsupported resource type for secret scanning",
			"resource_type", resource.ResourceType,
			"resource_id", resource.ResourceID,
			"template_id", resource.Properties["templateID"])
	}

	return l.Outputs(), nil
}

func (l *AzureFindSecretsLink) processVMUserData(ctx context.Context, resource *output.CloudResource) error {
	subscriptionID := resource.AccountRef

	// Parse resource ID to get resource group and VM name
	resourceGroup, vmName, err := l.parseVMResourceID(resource.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse VM resource ID: %w", err)
	}

	cred, err := helpers.NewAzureCredential()
	if err != nil {
		return fmt.Errorf("failed to get Azure credential: %w", err)
	}

	vmClient, err := armcompute.NewVirtualMachinesClient(subscriptionID, cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create VM client: %w", err)
	}

	// Get VM details including UserData
	userDataExpand := armcompute.InstanceViewTypesUserData
	vmDetails, err := vmClient.Get(ctx, resourceGroup, vmName, &armcompute.VirtualMachinesClientGetOptions{
		Expand: &userDataExpand,
	})
	if err != nil {
		l.Logger().Error("Failed to get VM details", "vm", vmName, "error", err.Error())
		return nil // Don't fail the whole process
	}

	if vmDetails.Properties != nil {
		// Process UserData
		if vmDetails.Properties.UserData != nil {
			l.Logger().Debug("Found VM UserData, sending to NoseyParker", "vm", vmName, "size", len(*vmDetails.Properties.UserData))
			npInput := types.NpInput{
				ContentBase64: *vmDetails.Properties.UserData,
				Provenance: types.NpProvenance{
					Platform:     "azure",
					ResourceType: "Microsoft.Compute/virtualMachines::UserData",
					ResourceID:   resource.ResourceID,
					Region:       resource.Region,
					AccountID:    subscriptionID,
				},
			}
			l.Send(npInput)
		} else {
			l.Logger().Debug("No UserData found on VM", "vm", vmName)
		}

		// Process OSProfile and CustomData
		if vmDetails.Properties.OSProfile != nil {
			if vmDetails.Properties.OSProfile.CustomData != nil {
				npInput := types.NpInput{
					ContentBase64: *vmDetails.Properties.OSProfile.CustomData,
					Provenance: types.NpProvenance{
						Platform:     "azure",
						ResourceType: "Microsoft.Compute/virtualMachines::CustomData",
						ResourceID:   resource.ResourceID,
						Region:       resource.Region,
						AccountID:    subscriptionID,
					},
				}
				l.Send(npInput)
			}

			if osProfileJson, err := json.Marshal(vmDetails.Properties.OSProfile); err == nil {
				npInput := types.NpInput{
					Content: string(osProfileJson),
					Provenance: types.NpProvenance{
						Platform:     "azure",
						ResourceType: "Microsoft.Compute/virtualMachines::OSProfile",
						ResourceID:   resource.ResourceID,
						Region:       resource.Region,
						AccountID:    subscriptionID,
					},
				}
				l.Send(npInput)
			}
		}
	}

	return nil
}

func (l *AzureFindSecretsLink) processVMExtensions(ctx context.Context, resource *output.CloudResource) error {
	subscriptionID := resource.AccountRef

	// Parse resource ID to get resource group and VM name
	resourceGroup, vmName, err := l.parseVMResourceID(resource.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse VM resource ID: %w", err)
	}

	cred, err := helpers.NewAzureCredential()
	if err != nil {
		return fmt.Errorf("failed to get Azure credential: %w", err)
	}

	// Create VM extensions client
	extClient, err := armcompute.NewVirtualMachineExtensionsClient(subscriptionID, cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create VM extensions client: %w", err)
	}

	// List extensions for this VM
	extensionResult, err := extClient.List(ctx, resourceGroup, vmName, &armcompute.VirtualMachineExtensionsClientListOptions{})
	if err != nil {
		l.Logger().Error("Failed to list VM extensions", "vm", vmName, "error", err.Error())
		return nil // Don't fail the whole process
	}

	if extensionResult.Value != nil {
		for _, extension := range extensionResult.Value {
			if extension.Properties != nil {
				// Convert extension properties to JSON for scanning
				extContent, err := json.Marshal(extension.Properties)
				if err != nil {
					l.Logger().Error("Failed to marshal extension properties", "vm", vmName, "extension", *extension.Name, "error", err.Error())
					continue
				}

				npInput := types.NpInput{
					Content: string(extContent),
					Provenance: types.NpProvenance{
						Platform:     "azure",
						ResourceType: "Microsoft.Compute/virtualMachines::Extensions",
						ResourceID:   fmt.Sprintf("%s/extensions/%s", resource.ResourceID, *extension.Name),
						Region:       resource.Region,
						AccountID:    subscriptionID,
					},
				}
				l.Send(npInput)
			}
		}
	}

	return nil
}

func (l *AzureFindSecretsLink) processFunctionAppConfig(ctx context.Context, resource *output.CloudResource) error {
	subscriptionID := resource.AccountRef

	// Parse resource ID to get resource group and app name
	resourceGroup, appName, err := l.parseFunctionAppResourceID(resource.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse Function App resource ID: %w", err)
	}

	cred, err := helpers.NewAzureCredential()
	if err != nil {
		return fmt.Errorf("failed to get Azure credential: %w", err)
	}

	webClient, err := armappservice.NewWebAppsClient(subscriptionID, cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create web client: %w", err)
	}

	// Application Settings
	appSettings, err := webClient.ListApplicationSettings(ctx, resourceGroup, appName, nil)
	if err != nil {
		l.Logger().Error("Failed to list application settings", "app", appName, "error", err.Error())
		return nil // Don't fail the whole process
	}

	if len(appSettings.Properties) > 0 {
		if settingsJson, err := json.Marshal(appSettings.Properties); err == nil {
			npInput := types.NpInput{
				Content: string(settingsJson),
				Provenance: types.NpProvenance{
					Platform:     "azure",
					ResourceType: "Microsoft.Web/sites::AppSettings",
					ResourceID:   resource.ResourceID,
					Region:       resource.Region,
					AccountID:    subscriptionID,
				},
			}
			l.Send(npInput)
		}
	}

	return nil
}

func (l *AzureFindSecretsLink) processFunctionAppConnections(ctx context.Context, resource *output.CloudResource) error {
	subscriptionID := resource.AccountRef

	// Parse resource ID to get resource group and app name
	resourceGroup, appName, err := l.parseFunctionAppResourceID(resource.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse Function App resource ID: %w", err)
	}

	cred, err := helpers.NewAzureCredential()
	if err != nil {
		return fmt.Errorf("failed to get Azure credential: %w", err)
	}

	webClient, err := armappservice.NewWebAppsClient(subscriptionID, cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create web client: %w", err)
	}

	// Connection Strings
	connStrings, err := webClient.ListConnectionStrings(ctx, resourceGroup, appName, nil)
	if err != nil {
		l.Logger().Error("Failed to list connection strings", "app", appName, "error", err.Error())
		return nil // Don't fail the whole process
	}

	if connStrings.Properties != nil {
		if stringsJson, err := json.Marshal(connStrings.Properties); err == nil {
			npInput := types.NpInput{
				Content: string(stringsJson),
				Provenance: types.NpProvenance{
					Platform:     "azure",
					ResourceType: "Microsoft.Web/sites::ConnectionStrings",
					ResourceID:   resource.ResourceID,
					Region:       resource.Region,
					AccountID:    subscriptionID,
				},
			}
			l.Send(npInput)
		}
	}

	return nil
}

func (l *AzureFindSecretsLink) processFunctionAppKeys(ctx context.Context, resource *output.CloudResource) error {
	subscriptionID := resource.AccountRef

	// Parse resource ID to get resource group and app name
	resourceGroup, appName, err := l.parseFunctionAppResourceID(resource.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse Function App resource ID: %w", err)
	}

	cred, err := helpers.NewAzureCredential()
	if err != nil {
		return fmt.Errorf("failed to get Azure credential: %w", err)
	}

	webClient, err := armappservice.NewWebAppsClient(subscriptionID, cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create web client: %w", err)
	}

	// Host Keys (Function App level keys)
	hostKeys, err := webClient.ListHostKeys(ctx, resourceGroup, appName, nil)
	if err != nil {
		l.Logger().Error("Failed to list host keys", "app", appName, "error", err.Error())
		return nil // Don't fail the whole process
	}

	if hostKeysJson, err := json.Marshal(hostKeys); err == nil {
		npInput := types.NpInput{
			Content: string(hostKeysJson),
			Provenance: types.NpProvenance{
				Platform:     "azure",
				ResourceType: "Microsoft.Web/sites::HostKeys",
				ResourceID:   resource.ResourceID,
				Region:       resource.Region,
				AccountID:    subscriptionID,
			},
		}
		l.Send(npInput)
	}

	return nil
}

func (l *AzureFindSecretsLink) parseVMResourceID(resourceID string) (resourceGroup, vmName string, err error) {
	// Extract actual Azure resource ID from aurelian key format
	// Format: #azureresource#subscription#/subscriptions/...
	parts := strings.Split(resourceID, "#")
	if len(parts) < 4 {
		return "", "", fmt.Errorf("invalid aurelian resource key format")
	}
	actualResourceID := parts[3] // The actual Azure resource ID

	parsed, err := helpers.ParseAzureResourceID(actualResourceID)
	if err != nil {
		return "", "", err
	}

	resourceGroup = parsed["resourceGroups"]
	vmName = parsed["virtualMachines"]

	if resourceGroup == "" || vmName == "" {
		return "", "", fmt.Errorf("invalid VM resource ID format")
	}

	return resourceGroup, vmName, nil
}

func (l *AzureFindSecretsLink) parseFunctionAppResourceID(resourceID string) (resourceGroup, appName string, err error) {
	// Extract actual Azure resource ID from aurelian key format
	parts := strings.Split(resourceID, "#")
	if len(parts) < 4 {
		return "", "", fmt.Errorf("invalid aurelian resource key format")
	}
	actualResourceID := parts[3] // The actual Azure resource ID

	parsed, err := helpers.ParseAzureResourceID(actualResourceID)
	if err != nil {
		return "", "", err
	}

	resourceGroup = parsed["resourceGroups"]
	appName = parsed["sites"]

	if resourceGroup == "" || appName == "" {
		return "", "", fmt.Errorf("invalid Function App resource ID format")
	}

	return resourceGroup, appName, nil
}

func (l *AzureFindSecretsLink) processAutomationAccount(ctx context.Context, resource *output.CloudResource) error {
	subscriptionID := resource.AccountRef

	// Parse resource ID to get resource group and automation account name
	resourceGroup, automationAccountName, err := l.parseAutomationAccountResourceID(resource.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse Automation Account resource ID: %w", err)
	}

	l.Logger().Debug("Processing automation account for secrets", "automation_account", automationAccountName, "resource_group", resourceGroup)

	// Process automation variables
	err = l.processAutomationVariables(subscriptionID, resourceGroup, automationAccountName, resource.ResourceID)
	if err != nil {
		l.Logger().Error("Failed to process automation variables", "error", err.Error())
	}

	// Process automation runbooks
	err = l.processAutomationRunbooks(subscriptionID, resourceGroup, automationAccountName, resource.ResourceID)
	if err != nil {
		l.Logger().Error("Failed to process automation runbooks", "error", err.Error())
	}

	return nil
}

func (l *AzureFindSecretsLink) processAutomationVariables(subscriptionID, resourceGroup, automationAccountName, resourceID string) error {
	l.Logger().Debug("Processing automation variables", "automation_account", automationAccountName)

	// For now, create a placeholder NPInput to indicate we found an automation account
	// In a full implementation, we would make the REST API call to get actual variables
	npInput := types.NpInput{
		Content: fmt.Sprintf("Automation Account Variables for %s", automationAccountName),
		Provenance: types.NpProvenance{
			Platform:     "azure",
			ResourceType: "Microsoft.Automation/automationAccounts::Variables",
			ResourceID:   fmt.Sprintf("%s/variables", resourceID),
			Region:       "",
			AccountID:    subscriptionID,
		},
	}
	l.Send(npInput)

	return nil
}

func (l *AzureFindSecretsLink) processAutomationRunbooks(subscriptionID, resourceGroup, automationAccountName, resourceID string) error {
	l.Logger().Debug("Processing automation runbooks", "automation_account", automationAccountName)

	// Create a placeholder NPInput for runbooks
	npInput := types.NpInput{
		Content: fmt.Sprintf("Automation Account Runbooks for %s", automationAccountName),
		Provenance: types.NpProvenance{
			Platform:     "azure",
			ResourceType: "Microsoft.Automation/automationAccounts::Runbooks",
			ResourceID:   fmt.Sprintf("%s/runbooks", resourceID),
			Region:       "",
			AccountID:    subscriptionID,
		},
	}
	l.Send(npInput)

	return nil
}

func (l *AzureFindSecretsLink) parseAutomationAccountResourceID(resourceID string) (resourceGroup, automationAccountName string, err error) {
	// Extract actual Azure resource ID from aurelian key format
	parts := strings.Split(resourceID, "#")
	if len(parts) < 4 {
		return "", "", fmt.Errorf("invalid aurelian resource key format")
	}
	actualResourceID := parts[3] // The actual Azure resource ID

	parsed, err := helpers.ParseAzureResourceID(actualResourceID)
	if err != nil {
		return "", "", err
	}

	resourceGroup = parsed["resourceGroups"]
	automationAccountName = parsed["automationAccounts"]

	if resourceGroup == "" || automationAccountName == "" {
		return "", "", fmt.Errorf("invalid Automation Account resource ID format")
	}

	return resourceGroup, automationAccountName, nil
}
