package extraction

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("Microsoft.Compute/virtualMachines", "vm-userdata", extractVMUserData)
	mustRegister("Microsoft.Compute/virtualMachines", "vm-extensions", extractVMExtensions)
}

// parseVMResourceID extracts resource group and VM name from a standard Azure resource ID.
func parseVMResourceID(resourceID string) (resourceGroup, vmName string, err error) {
	rg, name, err := parseResourceID(resourceID, "resourceGroups", "virtualMachines")
	if err != nil {
		return "", "", fmt.Errorf("invalid VM resource ID %q: %w", resourceID, err)
	}
	return rg, name, nil
}

// parseResourceID is a generic parser for Azure resource IDs.
// It extracts the values for the given segment keys from a path like:
// /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}
func parseResourceID(resourceID, rgKey, resourceKey string) (rgValue, resourceValue string, err error) {
	parts := strings.Split(strings.TrimPrefix(resourceID, "/"), "/")
	segments := make(map[string]string)
	for i := 0; i+1 < len(parts); i += 2 {
		segments[strings.ToLower(parts[i])] = parts[i+1]
	}

	rgValue = segments[strings.ToLower(rgKey)]
	resourceValue = segments[strings.ToLower(resourceKey)]
	if rgValue == "" || resourceValue == "" {
		return "", "", fmt.Errorf("missing %s or %s in resource ID", rgKey, resourceKey)
	}
	return rgValue, resourceValue, nil
}

func extractVMUserData(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	rg, vmName, err := parseVMResourceID(r.ResourceID)
	if err != nil {
		return err
	}

	vmClient, err := armcompute.NewVirtualMachinesClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create VM client: %w", err)
	}

	userDataExpand := armcompute.InstanceViewTypesUserData
	vmDetails, err := vmClient.Get(ctx.Context, rg, vmName, &armcompute.VirtualMachinesClientGetOptions{
		Expand: &userDataExpand,
	})
	if err != nil {
		slog.Warn("failed to get VM details", "vm", vmName, "error", err)
		return nil
	}

	if vmDetails.Properties == nil {
		return nil
	}

	// UserData (base64-encoded)
	hasUserData := vmDetails.Properties.UserData != nil && *vmDetails.Properties.UserData != ""
	if hasUserData {
		decoded, err := base64.StdEncoding.DecodeString(*vmDetails.Properties.UserData)
		if err != nil {
			slog.Warn("failed to decode VM UserData", "vm", vmName, "error", err)
		} else if len(decoded) > 0 {
			out.Send(output.ScanInputFromAzureResource(r, "UserData", decoded))
		}
	}

	if vmDetails.Properties.OSProfile == nil {
		return nil
	}

	// CustomData (base64-encoded, in OSProfile)
	hasCustomData := vmDetails.Properties.OSProfile.CustomData != nil && *vmDetails.Properties.OSProfile.CustomData != ""
	if hasCustomData {
		decoded, err := base64.StdEncoding.DecodeString(*vmDetails.Properties.OSProfile.CustomData)
		if err != nil {
			slog.Warn("failed to decode VM CustomData", "vm", vmName, "error", err)
		} else if len(decoded) > 0 {
			out.Send(output.ScanInputFromAzureResource(r, "CustomData", decoded))
		}
	}

	// OSProfile as JSON
	osProfileJSON, err := json.Marshal(vmDetails.Properties.OSProfile)
	if err == nil && len(osProfileJSON) > 2 {
		out.Send(output.ScanInputFromAzureResource(r, "OSProfile", osProfileJSON))
	}

	return nil
}

func extractVMExtensions(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	rg, vmName, err := parseVMResourceID(r.ResourceID)
	if err != nil {
		return err
	}

	extClient, err := armcompute.NewVirtualMachineExtensionsClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create VM extensions client: %w", err)
	}

	result, err := extClient.List(ctx.Context, rg, vmName, &armcompute.VirtualMachineExtensionsClientListOptions{})
	if err != nil {
		slog.Warn("failed to list VM extensions", "vm", vmName, "error", err)
		return nil
	}

	for _, ext := range result.Value {
		if ext.Properties == nil || ext.Name == nil {
			continue
		}
		content, err := json.Marshal(ext.Properties)
		if err != nil {
			slog.Warn("failed to marshal extension properties", "vm", vmName, "ext", *ext.Name, "error", err)
			continue
		}
		label := fmt.Sprintf("Extension:%s", *ext.Name)
		out.Send(output.ScanInputFromAzureResource(r, label, content))
	}

	return nil
}
