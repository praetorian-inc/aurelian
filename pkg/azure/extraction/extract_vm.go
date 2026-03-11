package extraction

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("microsoft.compute/virtualmachines", "vm-userdata", extractVMUserData)
	mustRegister("microsoft.compute/virtualmachines", "vm-extensions", extractVMExtensions)
}

func extractVMUserData(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, resourceGroup, segments, err := parseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse VM resource ID: %w", err)
	}
	vmName := segments["virtualMachines"]
	if vmName == "" {
		return fmt.Errorf("no virtualMachines segment in resource ID %s", r.ResourceID)
	}

	vmClient, err := armcompute.NewVirtualMachinesClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create VM client: %w", err)
	}

	userDataExpand := armcompute.InstanceViewTypesUserData
	vmDetails, err := vmClient.Get(ctx.Context, resourceGroup, vmName, &armcompute.VirtualMachinesClientGetOptions{
		Expand: &userDataExpand,
	})
	if err != nil {
		return handleExtractError(err, "vm-userdata", r.ResourceID)
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
			out.Send(output.ScanInputFromAzureResource(r, "VM UserData", decoded))
		}
	}

	if vmDetails.Properties.OSProfile == nil {
		return nil
	}

	// CustomData (base64-encoded)
	hasCustomData := vmDetails.Properties.OSProfile.CustomData != nil && *vmDetails.Properties.OSProfile.CustomData != ""
	if hasCustomData {
		decoded, err := base64.StdEncoding.DecodeString(*vmDetails.Properties.OSProfile.CustomData)
		if err != nil {
			slog.Warn("failed to decode VM CustomData", "vm", vmName, "error", err)
		} else if len(decoded) > 0 {
			out.Send(output.ScanInputFromAzureResource(r, "VM CustomData", decoded))
		}
	}

	// OSProfile JSON
	osProfileJSON, err := json.Marshal(vmDetails.Properties.OSProfile)
	if err == nil && len(osProfileJSON) > 2 {
		out.Send(output.ScanInputFromAzureResource(r, "VM OSProfile", osProfileJSON))
	}

	return nil
}

func extractVMExtensions(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, resourceGroup, segments, err := parseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse VM resource ID: %w", err)
	}
	vmName := segments["virtualMachines"]
	if vmName == "" {
		return fmt.Errorf("no virtualMachines segment in resource ID %s", r.ResourceID)
	}

	extClient, err := armcompute.NewVirtualMachineExtensionsClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create VM extensions client: %w", err)
	}

	extResult, err := extClient.List(ctx.Context, resourceGroup, vmName, nil)
	if err != nil {
		return handleExtractError(err, "vm-extensions", r.ResourceID)
	}

	if extResult.Value == nil {
		return nil
	}

	for _, ext := range extResult.Value {
		if ext.Properties == nil {
			continue
		}
		content, err := json.Marshal(ext.Properties)
		if err != nil {
			slog.Warn("failed to marshal extension properties", "vm", vmName, "error", err)
			continue
		}
		extName := ""
		if ext.Name != nil {
			extName = *ext.Name
		}
		label := fmt.Sprintf("VM Extension: %s", extName)
		out.Send(output.ScanInputFromAzureResource(r, label, content))
	}

	return nil
}
