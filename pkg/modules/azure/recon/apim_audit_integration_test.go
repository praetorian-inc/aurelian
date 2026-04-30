//go:build integration

package recon

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAzureAPIMAudit exercises the apim-audit module end-to-end against the
// terraform fixture under test/terraform/azure/recon/apim-audit. The fixture
// stands up two APIM Consumption services with seven APIs configured to cover
// every authentication signal the module checks (none, JWT, IP filter, header
// check, product subscription, service-scope inheritance, and an MCP-shaped
// API), plus one APIM backend pointing at a publicly-reachable App Service.
//
// Expected positives (3 risks):
//   - azure-apim-missing-auth         Critical → unauth-api on apim1
//   - azure-apim-mcp-missing-auth     Critical → fake-mcp-api on apim1 (is_mcp_server=true)
//   - azure-apim-backend-direct-access High    → public-appservice-backend on apim1
//
// Expected negatives — these APIs MUST NOT be flagged:
//   - jwt-api          (API-scope validate-jwt)
//   - ipfilter-api     (API-scope ip-filter)
//   - checkheader-api  (API-scope check-header)
//   - product-auth-api (product-scope JWT + subscription-required)
//   - inherits-auth-api (service-scope validate-jwt on apim2)
func TestAzureAPIMAudit(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/apim-audit")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAzure, plugin.CategoryRecon, "apim-audit")
	if !ok {
		t.Fatal("azure apim-audit module not registered in plugin system")
	}

	subscriptionID := fixture.Output("subscription_id")

	results, err := testutil.RunAndCollect(t, mod, plugin.Config{
		Args: map[string]any{
			"subscription-ids": []string{subscriptionID},
		},
		Context: context.Background(),
	})
	require.NoError(t, err)
	testutil.AssertMinResults(t, results, 3)

	// ----------------------------------------------------------------
	// Index risks for precise per-resource lookups.
	// ----------------------------------------------------------------
	type riskWithCtx struct {
		Risk   output.AurelianRisk
		CtxMap map[string]any
	}
	var allRisks []riskWithCtx
	byName := make(map[string][]riskWithCtx)
	byDedup := make(map[string]riskWithCtx)
	for _, r := range results {
		risk, ok := r.(output.AurelianRisk)
		if !ok {
			continue
		}
		var ctx map[string]any
		require.NoError(t, json.Unmarshal(risk.Context, &ctx),
			"risk %q has invalid JSON context", risk.Name)
		rc := riskWithCtx{Risk: risk, CtxMap: ctx}
		allRisks = append(allRisks, rc)
		byName[risk.Name] = append(byName[risk.Name], rc)
		byDedup[risk.DeduplicationID] = rc
	}
	require.NotEmpty(t, allRisks, "module produced no AurelianRisk results")

	apim1ID := fixture.Output("apim1_id")
	apim2ID := fixture.Output("apim2_id")

	// ================================================================
	// Positive: missing-auth check
	// ================================================================
	t.Run("flags unauth-api as azure-apim-missing-auth Critical", func(t *testing.T) {
		dedup := fixture.Output("unauth_api_id")
		rc, present := byDedup[dedup]
		require.True(t, present,
			"no risk found with DeduplicationID %q (got %d total risks)", dedup, len(allRisks))
		assert.Equal(t, "azure-apim-missing-auth", rc.Risk.Name)
		assert.Equal(t, output.RiskSeverityCritical, rc.Risk.Severity)
		assert.Equal(t, apim1ID, rc.Risk.ImpactedResourceID)

		isMCP, _ := rc.CtxMap["is_mcp_server"].(bool)
		assert.False(t, isMCP, "unauth-api must not be classified as an MCP server")

		subReq, _ := rc.CtxMap["subscription_required"].(bool)
		assert.False(t, subReq, "fixture's unauth-api has subscription_required=false")

		assert.Equal(t, "unauth-api", rc.CtxMap["api_id"])
	})

	t.Run("flags fake-mcp-api as azure-apim-mcp-missing-auth with is_mcp_server=true", func(t *testing.T) {
		dedup := fixture.Output("fake_mcp_api_id")
		rc, present := byDedup[dedup]
		require.True(t, present, "no risk found with DeduplicationID %q", dedup)
		assert.Equal(t, "azure-apim-mcp-missing-auth", rc.Risk.Name,
			"MCP-shaped APIs must use the mcp-specific risk name for downstream filtering")
		assert.Equal(t, output.RiskSeverityCritical, rc.Risk.Severity)
		assert.Equal(t, apim1ID, rc.Risk.ImpactedResourceID)

		isMCP, _ := rc.CtxMap["is_mcp_server"].(bool)
		assert.True(t, isMCP,
			"fake-mcp-api has /mcp /sse /messages operations and must be labelled MCP")
	})

	// ================================================================
	// Positive: backend-direct-access check
	// ================================================================
	t.Run("flags public-appservice-backend as azure-apim-backend-direct-access High", func(t *testing.T) {
		backendName := fixture.Output("public_backend_name")
		dedup := apim1ID + "/backend/" + backendName
		rc, present := byDedup[dedup]
		require.True(t, present, "no risk found with DeduplicationID %q", dedup)
		assert.Equal(t, "azure-apim-backend-direct-access", rc.Risk.Name)
		assert.Equal(t, output.RiskSeverityHigh, rc.Risk.Severity)
		assert.Equal(t, apim1ID, rc.Risk.ImpactedResourceID)

		assert.Equal(t, backendName, rc.CtxMap["backend_name"])
		assert.Equal(t, fixture.Output("public_backend_url"), rc.CtxMap["backend_url"])
		assert.Equal(t, "azure-app-service", rc.CtxMap["category"])
		assert.Equal(t, "Enabled", rc.CtxMap["public_network_access"],
			"the App Service backend has public_network_access_enabled=true in fixture")

		correlated, _ := rc.CtxMap["correlated_resource_id"].(string)
		assert.NotEmpty(t, correlated, "ARG correlation must populate correlated_resource_id")
		assert.Equal(t,
			strings.ToLower(fixture.Output("public_app_service_id")),
			strings.ToLower(correlated),
			"correlated_resource_id should match the fixture's App Service")

		reason, _ := rc.CtxMap["reason"].(string)
		assert.Contains(t, reason, "publicNetworkAccess Enabled",
			"reason text should explain why this is reachable outside the gateway")
	})

	// ================================================================
	// Negative: secured APIs must NOT produce missing-auth risks
	// ================================================================
	securedAPIs := []struct {
		apiName    string
		outputKey  string
		protection string
	}{
		{"jwt-api", "jwt_api_id", "API-scope validate-jwt"},
		{"ipfilter-api", "ipfilter_api_id", "API-scope ip-filter"},
		{"checkheader-api", "checkheader_api_id", "API-scope check-header"},
		{"product-auth-api", "product_auth_api_id", "product-scope JWT + subscription-required"},
		{"inherits-auth-api", "inherits_auth_api_id", "service-scope validate-jwt (apim2)"},
	}
	for _, tt := range securedAPIs {
		t.Run("does not flag "+tt.apiName+" ("+tt.protection+")", func(t *testing.T) {
			apiID := fixture.Output(tt.outputKey)
			_, present := byDedup[apiID]
			assert.False(t, present,
				"%s should NOT be flagged (%s) but found risk with DeduplicationID %q",
				tt.apiName, tt.protection, apiID)
		})
	}

	// ================================================================
	// Cross-finding invariants
	// ================================================================
	t.Run("missing-auth check produced exactly the two expected positives", func(t *testing.T) {
		total := len(byName["azure-apim-missing-auth"]) + len(byName["azure-apim-mcp-missing-auth"])
		assert.Equal(t, 2, total,
			"expected 2 missing-auth risks (unauth + mcp), got %d (names: missing-auth=%d, mcp=%d)",
			total, len(byName["azure-apim-missing-auth"]), len(byName["azure-apim-mcp-missing-auth"]))
	})

	t.Run("backend check produced at least one direct-access positive", func(t *testing.T) {
		assert.GreaterOrEqual(t, len(byName["azure-apim-backend-direct-access"]), 1)
	})

	t.Run("apim2 produced no risks (only API inherits auth, no backends)", func(t *testing.T) {
		for _, rc := range allRisks {
			assert.NotEqual(t, apim2ID, rc.Risk.ImpactedResourceID,
				"apim2 only has inherits-auth-api which inherits service-scope JWT — should be silent")
		}
	})

	t.Run("all risks have non-empty ImpactedResourceID", func(t *testing.T) {
		for _, rc := range allRisks {
			assert.NotEmpty(t, rc.Risk.ImpactedResourceID,
				"risk %q has empty ImpactedResourceID", rc.Risk.Name)
		}
	})

	t.Run("all risks reference an APIM service in ImpactedResourceID", func(t *testing.T) {
		for _, rc := range allRisks {
			assert.Contains(t, rc.Risk.ImpactedResourceID, "/Microsoft.ApiManagement/service/",
				"risk %q ImpactedResourceID should point at the APIM service", rc.Risk.Name)
		}
	})

	t.Run("all risks have non-empty DeduplicationID", func(t *testing.T) {
		for _, rc := range allRisks {
			assert.NotEmpty(t, rc.Risk.DeduplicationID,
				"risk %q has empty DeduplicationID", rc.Risk.Name)
		}
	})

	t.Run("no duplicate DeduplicationIDs across the run", func(t *testing.T) {
		seen := make(map[string]int)
		for _, rc := range allRisks {
			seen[rc.Risk.DeduplicationID]++
		}
		for dedup, count := range seen {
			assert.Equal(t, 1, count,
				"DeduplicationID %q appeared %d times — checks are emitting duplicate risks", dedup, count)
		}
	})

	t.Run("all risk names are within the expected set", func(t *testing.T) {
		valid := map[string]bool{
			"azure-apim-missing-auth":          true,
			"azure-apim-mcp-missing-auth":      true,
			"azure-apim-backend-direct-access": true,
			"azure-apim-backend-unverified":    true,
		}
		for _, rc := range allRisks {
			assert.True(t, valid[rc.Risk.Name],
				"unexpected risk name %q — module emitted a name outside the documented set", rc.Risk.Name)
		}
	})

	t.Run("missing-auth risks carry both api_id and apim_service_id in context", func(t *testing.T) {
		for _, rc := range byName["azure-apim-missing-auth"] {
			assert.NotEmpty(t, rc.CtxMap["api_id"], "missing-auth context.api_id should be populated")
			assert.NotEmpty(t, rc.CtxMap["apim_service_id"], "missing-auth context.apim_service_id should be populated")
		}
		for _, rc := range byName["azure-apim-mcp-missing-auth"] {
			assert.NotEmpty(t, rc.CtxMap["api_id"], "mcp-missing-auth context.api_id should be populated")
			isMCP, _ := rc.CtxMap["is_mcp_server"].(bool)
			assert.True(t, isMCP, "mcp-missing-auth context must always have is_mcp_server=true")
		}
	})
}
