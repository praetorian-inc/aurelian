package push

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/praetorian-inc/aurelian/pkg/azure/iam"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// TestGenerateIAMData collects live Azure IAM data and writes it to a JSON file.
// This is a helper test, not a regular test — run it manually to generate test data.
//
// Run with:
//
//	AZURE_SUBSCRIPTION_ID=<sub> AZURE_IAM_OUTPUT=/tmp/azure-iam.json \
//	  go test ./pkg/modules/azure/push/ -run TestGenerateIAMData -v -count=1 -timeout 30m
func TestGenerateIAMData(t *testing.T) {
	subID := os.Getenv("AZURE_SUBSCRIPTION_ID")
	if subID == "" {
		t.Skip("AZURE_SUBSCRIPTION_ID not set")
	}
	outFile := os.Getenv("AZURE_IAM_OUTPUT")
	if outFile == "" {
		outFile = "/tmp/azure-iam-consolidated.json"
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		t.Fatalf("credential: %v", err)
	}

	ctx := context.Background()
	consolidated := &types.AzureIAMConsolidated{}

	// Entra
	t.Log("Collecting Entra ID...")
	entraCollector := iam.NewEntraCollector(cred)
	entraData, err := entraCollector.Collect(ctx)
	if err != nil {
		slog.Warn("Entra failed", "error", err)
	} else {
		consolidated.EntraID = entraData
		t.Logf("  Users: %d, Groups: %d, SPs: %d, Apps: %d",
			entraData.Users.Len(), entraData.Groups.Len(),
			entraData.ServicePrincipals.Len(), entraData.Applications.Len())
	}

	// PIM
	t.Log("Collecting PIM...")
	pimCollector := iam.NewPIMCollector(cred)
	pimData, err := pimCollector.Collect(ctx)
	if err != nil {
		slog.Warn("PIM failed", "error", err)
	} else {
		consolidated.PIM = pimData
	}

	// RBAC
	t.Log("Collecting RBAC...")
	rbacCollector := iam.NewRBACCollector(cred)
	rbacData, err := rbacCollector.Collect(ctx, []string{subID})
	if err != nil {
		slog.Warn("RBAC failed", "error", err)
	} else {
		consolidated.RBAC = rbacData
	}

	// MgmtGroups
	t.Log("Collecting Management Groups...")
	mgCollector := iam.NewMgmtGroupsCollector(cred)
	mgData, err := mgCollector.Collect(ctx)
	if err != nil {
		slog.Warn("MgmtGroups failed", "error", err)
	} else {
		consolidated.ManagementGroups = mgData
	}

	// Metadata
	counts := make(map[string]int)
	if consolidated.EntraID != nil {
		counts["users"] = consolidated.EntraID.Users.Len()
		counts["groups"] = consolidated.EntraID.Groups.Len()
		counts["servicePrincipals"] = consolidated.EntraID.ServicePrincipals.Len()
		counts["applications"] = consolidated.EntraID.Applications.Len()
	}
	consolidated.Metadata = &types.CollectionMetadata{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Counts:    counts,
	}

	data, err := json.MarshalIndent(consolidated, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	if err := os.WriteFile(outFile, data, 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	t.Logf("Written %d bytes to %s", len(data), outFile)
}
