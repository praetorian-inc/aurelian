package extraction

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

const bootDiagMaxBytes = 5 * 1024 * 1024 // 5 MB

func init() {
	mustRegister("microsoft.compute/virtualmachines", "vm-bootdiag", extractVMBootDiag)
}

func extractVMBootDiag(ctx extractContext, r output.AzureResource, out *pipeline.P[output.ScanInput]) error {
	_, resourceGroup, segments, err := ParseAzureResourceID(r.ResourceID)
	if err != nil {
		return fmt.Errorf("failed to parse resource ID: %w", err)
	}
	vmName := segments["virtualMachines"]
	if vmName == "" {
		return fmt.Errorf("no virtualMachines segment in resource ID %s", r.ResourceID)
	}

	vmClient, err := armcompute.NewVirtualMachinesClient(r.SubscriptionID, ctx.Cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create VM client: %w", err)
	}

	result, err := vmClient.RetrieveBootDiagnosticsData(ctx.Context, resourceGroup, vmName, nil)
	if err != nil {
		return handleExtractError(err, "vm-bootdiag", r.ResourceID)
	}

	if result.SerialConsoleLogBlobURI == nil || *result.SerialConsoleLogBlobURI == "" {
		return nil
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return fmt.Errorf("refusing non-HTTPS redirect")
			}
			return nil
		},
	}

	resp, err := httpClient.Get(*result.SerialConsoleLogBlobURI)
	if err != nil {
		slog.Warn("failed to download boot diagnostics log", "vm", vmName, "error", err)
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("unexpected status downloading boot diagnostics log", "vm", vmName, "status", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, bootDiagMaxBytes))
	if err != nil {
		slog.Warn("failed to read boot diagnostics log", "vm", vmName, "error", err)
		return nil
	}

	if len(body) > 0 {
		out.Send(output.ScanInputFromAzureResource(r, "VM BootDiagnostics", body))
	}

	return nil
}
