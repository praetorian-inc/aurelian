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

func TestAzurePublicResources(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/public-resources")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAzure, plugin.CategoryRecon, "public-resources")
	if !ok {
		t.Fatal("azure public-resources module not registered in plugin system")
	}

	subscriptionID := fixture.Output("subscription_id")

	results, err := testutil.RunAndCollect(t, mod, plugin.Config{
		Args: map[string]any{
			"subscription-ids": []string{subscriptionID},
		},
		Context: context.Background(),
	})
	require.NoError(t, err)
	testutil.AssertMinResults(t, results, 20)

	// =====================================================================
	// Index risks by template ID for precise assertions.
	// =====================================================================

	type riskWithContext struct {
		Risk       output.AurelianRisk
		CtxMap     map[string]any
		Template   string
		ResourceID string
	}

	var all []riskWithContext
	byTemplate := make(map[string][]riskWithContext)
	for _, r := range results {
		risk, ok := r.(output.AurelianRisk)
		if !ok {
			continue
		}
		var ctx map[string]any
		require.NoError(t, json.Unmarshal(risk.Context, &ctx))
		tid, _ := ctx["templateId"].(string)
		rc := riskWithContext{
			Risk:       risk,
			CtxMap:     ctx,
			Template:   tid,
			ResourceID: risk.ImpactedResourceID,
		}
		all = append(all, rc)
		byTemplate[tid] = append(byTemplate[tid], rc)
	}

	// Helper: check if a fixture output exists and is non-empty.
	fixtureHasOutput := func(key string) bool {
		defer func() { recover() }() // Output() calls t.Fatalf on missing keys
		v := fixture.Output(key)
		return v != ""
	}

	// Helper: find a risk for a specific fixture resource within a template.
	findRisk := func(t *testing.T, templateID, fixtureResourceIDKey string) riskWithContext {
		t.Helper()
		expectedID := strings.ToLower(fixture.Output(fixtureResourceIDKey))
		require.NotEmpty(t, expectedID, "fixture output %q is empty", fixtureResourceIDKey)
		risks, ok := byTemplate[templateID]
		require.True(t, ok, "no findings for template %q", templateID)
		for _, rc := range risks {
			if strings.EqualFold(rc.ResourceID, expectedID) {
				return rc
			}
		}
		t.Fatalf("template %q has %d findings but none match fixture resource %q (%s)",
			templateID, len(risks), expectedID, fixtureResourceIDKey)
		return riskWithContext{} // unreachable
	}

	// Helper: assert a specific risk's common fields.
	// resourceNameSubstr is an environment-agnostic suffix (e.g., "-kv", "sa", "-aks")
	// that must appear in the ImpactedResourceID to confirm the right resource was caught.
	assertRisk := func(t *testing.T, rc riskWithContext, expectedTemplate string, expectedSeverity output.RiskSeverity, resourceNameSubstr string) {
		t.Helper()
		assert.True(t, strings.HasPrefix(rc.Risk.Name, "public-azure-resource-"),
			"template %s: risk name %q should have prefix public-azure-resource-", expectedTemplate, rc.Risk.Name)
		assert.NotEmpty(t, rc.Risk.DeduplicationID,
			"template %s: risk should have DeduplicationID", expectedTemplate)
		assert.Equal(t, expectedSeverity, rc.Risk.Severity,
			"template %s: expected severity %s, got %s", expectedTemplate, expectedSeverity, rc.Risk.Severity)
		assert.Equal(t, expectedTemplate, rc.Template)
		assert.NotEmpty(t, rc.Risk.ImpactedResourceID)
		assert.NotEmpty(t, rc.Risk.Context)
		assert.Contains(t, strings.ToLower(rc.Risk.ImpactedResourceID), strings.ToLower(resourceNameSubstr),
			"template %s: ImpactedResourceID %q should contain resource name substring %q",
			expectedTemplate, rc.Risk.ImpactedResourceID, resourceNameSubstr)
	}

	// Per-template assertions: verify each template found the expected fixture resource
	// with the correct severity and resource name substring.
	templateTests := []struct {
		templateID string
		fixtureKey string
		severity   output.RiskSeverity
		substr     string
		optional   bool // skip if fixture output is missing
	}{
		// Storage & Data
		{"storage_accounts_public_access", "storage_account_id", output.RiskSeverityHigh, "sa", false},
		{"key_vault_public_access", "key_vault_id", output.RiskSeverityHigh, "-kv", false},
		{"cosmos_db_public_access", "cosmos_db_id", output.RiskSeverityHigh, "-cosmos", false},
		{"redis_cache_public_access", "redis_cache_id", output.RiskSeverityLow, "-redis", false},
		{"app_configuration_public_access", "app_configuration_id", output.RiskSeverityMedium, "-appconf", false},
		// Databases
		{"sql_servers_public_access", "sql_server_id", output.RiskSeverityHigh, "-w-sql", true},
		{"postgresql_flexible_server_public_access", "postgresql_server_id", output.RiskSeverityMedium, "-pg", false},
		// Container & Registry
		{"container_registries_public_access", "acr_id", output.RiskSeverityHigh, "acr", false},
		{"acr_anonymous_pull_access", "acr_anon_pull_id", output.RiskSeverityHigh, "acranon", false},
		{"container_apps_public_access", "container_app_id", output.RiskSeverityMedium, "-w-ca", true},
		{"container_instances_public_access", "container_instance_id", output.RiskSeverityMedium, "-ci", false},
		{"aks_public_access", "aks_id", output.RiskSeverityHigh, "-aks", false},
		// AI & Search
		{"cognitive_services_public_access", "cognitive_account_id", output.RiskSeverityMedium, "-cog", false},
		{"search_service_public_access", "search_service_id", output.RiskSeverityMedium, "-search", false},
		// Compute
		{"virtual_machines_public_access", "virtual_machine_id", output.RiskSeverityHigh, "-vm", false},
		{"databricks_public_access", "databricks_workspace_id", output.RiskSeverityMedium, "-dbw", false},
		// IoT & Messaging
		{"iot_hub_public_access", "iot_hub_id", output.RiskSeverityMedium, "-iot", false},
		{"event_grid_topics_public_access", "event_grid_topic_id", output.RiskSeverityMedium, "-egt", false},
		{"notification_hubs_public_access", "notification_hub_namespace_id", output.RiskSeverityMedium, "-nhns", false},
		{"service_bus_public_access", "service_bus_id", output.RiskSeverityLow, "-sbus", false},
		{"event_hub_public_access", "event_hub_id", output.RiskSeverityHigh, "-eh", false},
		// Analytics & Integration
		{"synapse_public_access", "synapse_workspace_id", output.RiskSeverityMedium, "-w-syn", true},
		{"ml_workspace_public_access", "ml_workspace_id", output.RiskSeverityMedium, "-w-mlw", true},
		{"logic_apps_public_access", "logic_app_id", output.RiskSeverityMedium, "-la", false},
		{"data_factory_public_access", "data_factory_id", output.RiskSeverityLow, "-adf", false},
		{"log_analytics_public_access", "log_analytics_id", output.RiskSeverityLow, "-law", false},
		{"data_explorer_public_access", "kusto_cluster_id", output.RiskSeverityMedium, "kusto", false},
		// Networking
		{"api_management_public_access", "api_management_id", output.RiskSeverityMedium, "-apim", false},
		{"load_balancers_public", "load_balancer_id", output.RiskSeverityHigh, "-lb", false},
		{"application_gateway_public_access", "application_gateway_id", output.RiskSeverityMedium, "-appgw", false},
	}

	for _, tt := range templateTests {
		t.Run(tt.templateID, func(t *testing.T) {
			if tt.optional && !fixtureHasOutput(tt.fixtureKey) {
				t.Skipf("%s not provisioned in this environment", tt.fixtureKey)
			}
			rc := findRisk(t, tt.templateID, tt.fixtureKey)
			assertRisk(t, rc, tt.templateID, tt.severity, tt.substr)
		})
	}

	// =====================================================================
	// Negative tests — secure resources must NOT produce findings
	// =====================================================================

	// Helper: assert a secure resource ID does not appear in any finding.
	assertNotFlagged := func(t *testing.T, fixtureKey, description string) {
		t.Helper()
		if !fixtureHasOutput(fixtureKey) {
			t.Skipf("%s not provisioned", description)
		}
		secureID := strings.ToLower(fixture.Output(fixtureKey))
		for _, rc := range all {
			assert.NotEqual(t, strings.ToLower(rc.ResourceID), secureID,
				"%s should NOT be flagged but was by template %q", description, rc.Template)
		}
	}

	t.Run("secure storage account not flagged", func(t *testing.T) {
		assertNotFlagged(t, "secure_storage_account_id", "secure storage account (public access disabled)")
	})

	t.Run("secure key vault not flagged", func(t *testing.T) {
		assertNotFlagged(t, "secure_key_vault_id", "secure key vault (deny by default)")
	})

	t.Run("secure cosmos db not flagged", func(t *testing.T) {
		assertNotFlagged(t, "secure_cosmos_db_id", "secure Cosmos DB (public access disabled)")
	})

	t.Run("secure container registry not flagged", func(t *testing.T) {
		assertNotFlagged(t, "secure_acr_id", "secure ACR (public access disabled, admin disabled)")
	})

	t.Run("secure app configuration not flagged", func(t *testing.T) {
		assertNotFlagged(t, "secure_app_configuration_id", "secure App Configuration (public access disabled)")
	})

	// =====================================================================
	// Cross-finding invariants
	// =====================================================================

	t.Run("all risks have granular name with resource type slug", func(t *testing.T) {
		for _, rc := range all {
			assert.True(t, strings.HasPrefix(rc.Risk.Name, "public-azure-resource-"),
				"template %q: risk name %q should have prefix public-azure-resource-", rc.Template, rc.Risk.Name)
			assert.NotEmpty(t, rc.Risk.DeduplicationID,
				"template %q: risk should have DeduplicationID set to resource type", rc.Template)
		}
	})

	t.Run("all risks have valid severity", func(t *testing.T) {
		validSeverities := map[output.RiskSeverity]bool{
			output.RiskSeverityInfo: true, output.RiskSeverityLow: true,
			output.RiskSeverityMedium: true, output.RiskSeverityHigh: true,
			output.RiskSeverityCritical: true,
		}
		for _, rc := range all {
			assert.True(t, validSeverities[rc.Risk.Severity],
				"template %q: invalid severity %q", rc.Template, rc.Risk.Severity)
		}
	})

	t.Run("all risks have non-empty resource ID", func(t *testing.T) {
		for _, rc := range all {
			assert.NotEmpty(t, rc.Risk.ImpactedResourceID,
				"template %q: ImpactedResourceID must not be empty", rc.Template)
		}
	})

	t.Run("all risks have valid JSON context with templateId", func(t *testing.T) {
		for _, rc := range all {
			assert.NotEmpty(t, rc.Template,
				"risk context must contain templateId")
		}
	})

	t.Run("all risks have resourceId in context", func(t *testing.T) {
		for _, rc := range all {
			resID, _ := rc.CtxMap["resourceId"].(string)
			assert.NotEmpty(t, resID,
				"template %q: context should contain resourceId", rc.Template)
		}
	})

	t.Run("most risks have resourceType in context", func(t *testing.T) {
		withType := 0
		for _, rc := range all {
			resType, _ := rc.CtxMap["resourceType"].(string)
			if resType != "" {
				withType++
			}
		}
		// At least 80% of findings should have resourceType populated.
		ratio := float64(withType) / float64(len(all))
		assert.Greater(t, ratio, 0.8,
			"only %d/%d findings have resourceType in context", withType, len(all))
	})

	t.Run("no duplicate findings per resource per template", func(t *testing.T) {
		seen := make(map[string]int)
		for _, rc := range all {
			key := rc.Template + "|" + strings.ToLower(rc.ResourceID)
			seen[key]++
		}
		for key, count := range seen {
			assert.Equal(t, 1, count,
				"duplicate finding: %s appears %d times", key, count)
		}
	})

	t.Run("severity distribution has all expected levels", func(t *testing.T) {
		sevCounts := make(map[output.RiskSeverity]int)
		for _, rc := range all {
			sevCounts[rc.Risk.Severity]++
		}
		assert.Greater(t, sevCounts[output.RiskSeverityHigh], 0,
			"should have at least one high severity finding")
		assert.Greater(t, sevCounts[output.RiskSeverityMedium], 0,
			"should have at least one medium severity finding")
		assert.Greater(t, sevCounts[output.RiskSeverityLow], 0,
			"should have at least one low severity finding")
	})
}
