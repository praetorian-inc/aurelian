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
	mustRegister("microsoft.compute/virtualmachinescalesets", "vmss-userdata", extractVMSSUserData)
	mustRegister("microsoft.compute/virtualmachinescalesets", "vmss-extensions", extractVMSSExtensions)
}

func extractVMSSUserData(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, resourceGroup, segments, err := parseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse resource ID: %w", err)
	}
	name := segments["virtualMachineScaleSets"]
	if name == "" {
		return fmt.Errorf("no virtualMachineScaleSets segment in resource ID %s", r.ResourceID)
	}

	client, err := armcompute.NewVirtualMachineScaleSetsClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create VMSS client: %w", err)
	}

	expand := armcompute.ExpandTypesForGetVMScaleSetsUserData
	result, err := client.Get(ctx.Context, resourceGroup, name, &armcompute.VirtualMachineScaleSetsClientGetOptions{
		Expand: &expand,
	})
	if err != nil {
		return handleExtractError(err, "vmss-userdata", r.ResourceID)
	}

	if result.Properties == nil || result.Properties.VirtualMachineProfile == nil {
		return nil
	}
	profile := result.Properties.VirtualMachineProfile

	// UserData (base64-encoded)
	if profile.UserData != nil && *profile.UserData != "" {
		decoded, err := base64.StdEncoding.DecodeString(*profile.UserData)
		if err != nil {
			slog.Warn("failed to decode VMSS UserData", "vmss", name, "error", err)
		} else if len(decoded) > 0 {
			out.Send(output.ScanInputFromAzureResource(r, "VMSS UserData", decoded))
		}
	}

	// CustomData from OSProfile (base64-encoded)
	if profile.OSProfile != nil && profile.OSProfile.CustomData != nil && *profile.OSProfile.CustomData != "" {
		decoded, err := base64.StdEncoding.DecodeString(*profile.OSProfile.CustomData)
		if err != nil {
			slog.Warn("failed to decode VMSS CustomData", "vmss", name, "error", err)
		} else if len(decoded) > 0 {
			out.Send(output.ScanInputFromAzureResource(r, "VMSS CustomData", decoded))
		}
	}

	return nil
}

func extractVMSSExtensions(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, resourceGroup, segments, err := parseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse resource ID: %w", err)
	}
	name := segments["virtualMachineScaleSets"]
	if name == "" {
		return fmt.Errorf("no virtualMachineScaleSets segment in resource ID %s", r.ResourceID)
	}

	client, err := armcompute.NewVirtualMachineScaleSetExtensionsClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create VMSS extensions client: %w", err)
	}

	pager := client.NewListPager(resourceGroup, name, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx.Context)
		if err != nil {
			return handleExtractError(err, "vmss-extensions", r.ResourceID)
		}
		for _, ext := range page.Value {
			if ext.Properties == nil {
				continue
			}
			content, err := json.Marshal(ext.Properties)
			if err != nil {
				slog.Warn("failed to marshal VMSS extension properties", "vmss", name, "error", err)
				continue
			}
			extName := ""
			if ext.Name != nil {
				extName = *ext.Name
			}
			label := fmt.Sprintf("VMSS Extension: %s", extName)
			out.Send(output.ScanInputFromAzureResource(r, label, content))
		}
	}

	return nil
}
