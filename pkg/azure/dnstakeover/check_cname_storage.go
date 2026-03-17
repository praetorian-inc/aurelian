package dnstakeover

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

func init() {
	mustRegister("CNAME", "storage-takeover", checkBlobStorage)
}

const blobStorageSuffix = ".blob.core.windows.net"

func checkBlobStorage(ctx CheckContext, rec AzureDNSRecord, out *pipeline.P[model.AurelianModel]) error {
	for _, val := range rec.Values {
		if !strings.HasSuffix(strings.ToLower(val), blobStorageSuffix) {
			continue
		}

		accountName, _ := strings.CutSuffix(strings.ToLower(val), blobStorageSuffix)
		if accountName == "" {
			continue
		}

		available, err := checkStorageAccountAvailability(ctx, accountName)
		if err != nil {
			slog.Warn("storage account name check failed",
				"record", rec.RecordName, "account", accountName, "error", err)
			continue
		}

		if !available {
			continue
		}

		out.Send(NewTakeoverRisk(
			"storage-subdomain-takeover",
			output.RiskSeverityCritical,
			rec,
			map[string]any{
				"service":      "Blob Storage",
				"cname_target": val,
				"account_name": accountName,
				"description": fmt.Sprintf(
					"CNAME %q points to %s which is available for registration. "+
						"An attacker can create a storage account with this name and serve arbitrary content or intercept data.",
					rec.FQDN, val,
				),
				"remediation": "Remove the stale CNAME record or recreate the storage account.",
				"references": []string{
					"https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover",
				},
			},
		))
	}
	return nil
}

func checkStorageAccountAvailability(ctx CheckContext, accountName string) (bool, error) {
	client, err := armstorage.NewAccountsClient(ctx.SubscriptionID, ctx.Credential, nil)
	if err != nil {
		return false, fmt.Errorf("create storage client: %w", err)
	}

	resp, err := client.CheckNameAvailability(context.Background(), armstorage.AccountCheckNameAvailabilityParameters{
		Name: &accountName,
		Type: ptrTo("Microsoft.Storage/storageAccounts"),
	}, nil)
	if err != nil {
		return false, fmt.Errorf("check name availability: %w", err)
	}

	if resp.NameAvailable == nil {
		return false, nil
	}
	return *resp.NameAvailable, nil
}
