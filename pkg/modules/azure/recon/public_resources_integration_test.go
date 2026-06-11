//go:build integration

package recon

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeProof unmarshals a Risk's proof bytes into a structured capmodel.Proof.
func decodeProof(t *testing.T, risk capmodel.Risk) capmodel.Proof {
	t.Helper()
	var proof capmodel.Proof
	require.NoError(t, json.Unmarshal(risk.Proof, &proof), "proof should decode into capmodel.Proof")
	return proof
}

// sectionByTitle returns the named proof section, failing if it is absent.
func sectionByTitle(t *testing.T, proof capmodel.Proof, title string) capmodel.ProofSection {
	t.Helper()
	for _, s := range proof.Sections {
		if s.Title == title {
			return s
		}
	}
	require.Failf(t, "section not found", "proof has no %q section", title)
	return capmodel.ProofSection{}
}

// keyValueMap flattens a section's key/value rows into a map for assertions.
func keyValueMap(section capmodel.ProofSection) map[string]string {
	out := make(map[string]string)
	for _, el := range section.Elements {
		if el.KeyValue == nil {
			continue
		}
		for _, row := range el.KeyValue.Rows {
			out[row.Key] = row.Value
		}
	}
	return out
}

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

	type riskWithProof struct {
		Risk       capmodel.Risk
		Proof      capmodel.Proof
		Template   string
		ResourceID string
	}

	var all []riskWithProof
	byTemplate := make(map[string][]riskWithProof)
	for _, r := range results {
		risk, ok := r.(capmodel.Risk)
		if !ok {
			continue
		}
		proof := decodeProof(t, risk)
		tid := keyValueMap(sectionByTitle(t, proof, "Exposure"))["Template ID"]
		rc := riskWithProof{
			Risk:       risk,
			Proof:      proof,
			Template:   tid,
			ResourceID: risk.TargetName,
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
	findRisk := func(t *testing.T, templateID, fixtureResourceIDKey string) riskWithProof {
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
		return riskWithProof{} // unreachable
	}

	// Helper: assert a specific risk's common fields.
	// resourceNameSubstr is an environment-agnostic suffix (e.g., "-kv", "sa", "-aks")
	// that must appear in the TargetName to confirm the right resource was caught.
	assertRisk := func(t *testing.T, rc riskWithProof, expectedTemplate, expectedStatus, resourceNameSubstr string) {
		t.Helper()
		assert.Equal(t, "public-azure-resource", rc.Risk.Name)
		assert.Equal(t, "aurelian", rc.Risk.Source)
		assert.Equal(t, expectedStatus, rc.Risk.Status,
			"template %s: expected status %s, got %s", expectedTemplate, expectedStatus, rc.Risk.Status)
		assert.Equal(t, expectedTemplate, rc.Template)
		assert.NotEmpty(t, rc.Risk.TargetName)
		assert.NotEmpty(t, rc.Risk.Proof)
		assert.Contains(t, strings.ToLower(rc.Risk.TargetName), strings.ToLower(resourceNameSubstr),
			"template %s: TargetName %q should contain resource name substring %q",
			expectedTemplate, rc.Risk.TargetName, resourceNameSubstr)
	}

	// Per-template assertions: verify each template found the expected fixture resource
	// with the correct severity and resource name substring.
	templateTests := []struct {
		templateID string
		fixtureKey string
		status     string
		substr     string
		optional   bool // skip if fixture output is missing
	}{
		// Storage & Data
		{"storage_accounts_public_access", "storage_account_id", "TH", "sa", false},
		{"key_vault_public_access", "key_vault_id", "TH", "-kv", false},
		{"cosmos_db_public_access", "cosmos_db_id", "TH", "-cosmos", false},
		{"app_configuration_public_access", "app_configuration_id", "TM", "-appconf", false},
		// NOTE: redis_cache_public_access is intentionally NOT tested live. Classic
		// Azure Cache for Redis (Microsoft.Cache/Redis) — the only type the
		// redis_cache_public_access template matches — can no longer be created
		// account-wide following the Azure Cache for Redis retirement (HTTP 400,
		// reproduced in eastus2 and westus2). The fixture no longer provisions it.
		// Databases
		{"sql_servers_public_access", "sql_server_id", "TH", "-w-sql", true},
		{"postgresql_flexible_server_public_access", "postgresql_server_id", "TM", "-pg", false},
		// Container & Registry
		{"container_registries_public_access", "acr_id", "TH", "acr", false},
		{"acr_anonymous_pull_access", "acr_anon_pull_id", "TH", "acranon", false},
		{"container_apps_public_access", "container_app_id", "TM", "-w-ca", true},
		{"container_instances_public_access", "container_instance_id", "TM", "-ci", false},
		{"aks_public_access", "aks_id", "TH", "-aks", false},
		// AI & Search
		{"cognitive_services_public_access", "cognitive_account_id", "TM", "-cog", false},
		{"search_service_public_access", "search_service_id", "TM", "-search", false},
		// Compute
		{"virtual_machines_public_access", "virtual_machine_id", "TH", "-vm", false},
		{"databricks_public_access", "databricks_workspace_id", "TM", "-dbw", false},
		// IoT & Messaging
		{"iot_hub_public_access", "iot_hub_id", "TM", "-iot", false},
		{"event_grid_topics_public_access", "event_grid_topic_id", "TM", "-egt", false},
		{"notification_hubs_public_access", "notification_hub_namespace_id", "TM", "-nhns", false},
		{"service_bus_public_access", "service_bus_id", "TL", "-sbus", false},
		{"event_hub_public_access", "event_hub_id", "TH", "-eh", false},
		// Analytics & Integration
		{"synapse_public_access", "synapse_workspace_id", "TM", "-w-syn", true},
		{"ml_workspace_public_access", "ml_workspace_id", "TM", "-w-mlw", true},
		{"logic_apps_public_access", "logic_app_id", "TM", "-la", false},
		{"data_factory_public_access", "data_factory_id", "TL", "-adf", false},
		{"log_analytics_public_access", "log_analytics_id", "TL", "-law", false},
		{"data_explorer_public_access", "kusto_cluster_id", "TM", "kusto", false},
		// Networking
		{"api_management_public_access", "api_management_id", "TM", "-apim", false},
		{"load_balancers_public", "load_balancer_id", "TH", "-lb", false},
		{"application_gateway_public_access", "application_gateway_id", "TM", "-appgw", false},
	}

	for _, tt := range templateTests {
		t.Run(tt.templateID, func(t *testing.T) {
			if tt.optional && !fixtureHasOutput(tt.fixtureKey) {
				t.Skipf("%s not provisioned in this environment", tt.fixtureKey)
			}
			rc := findRisk(t, tt.templateID, tt.fixtureKey)
			assertRisk(t, rc, tt.templateID, tt.status, tt.substr)
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

	t.Run("all risks have name public-azure-resource", func(t *testing.T) {
		for _, rc := range all {
			assert.Equal(t, "public-azure-resource", rc.Risk.Name,
				"template %q: risk name should be public-azure-resource", rc.Template)
		}
	})

	t.Run("all risks have valid status", func(t *testing.T) {
		validStatuses := map[string]bool{"TI": true, "TL": true, "TM": true, "TH": true, "TC": true}
		for _, rc := range all {
			assert.True(t, validStatuses[rc.Risk.Status],
				"template %q: invalid status %q", rc.Template, rc.Risk.Status)
		}
	})

	t.Run("all risks have non-empty target name", func(t *testing.T) {
		for _, rc := range all {
			assert.NotEmpty(t, rc.Risk.TargetName,
				"template %q: TargetName must not be empty", rc.Template)
		}
	})

	t.Run("all risks have a Template ID in the Exposure section", func(t *testing.T) {
		for _, rc := range all {
			assert.NotEmpty(t, rc.Template,
				"proof Exposure section must contain a Template ID")
		}
	})

	t.Run("all risks have Resource ID matching TargetName", func(t *testing.T) {
		for _, rc := range all {
			resource := keyValueMap(sectionByTitle(t, rc.Proof, "Resource"))
			assert.Equal(t, rc.Risk.TargetName, resource["Resource ID"],
				"template %q: Resource ID row should match TargetName", rc.Template)
		}
	})

	t.Run("most risks have resource type populated", func(t *testing.T) {
		withType := 0
		for _, rc := range all {
			if keyValueMap(sectionByTitle(t, rc.Proof, "Resource"))["Resource Type"] != "" {
				withType++
			}
		}
		ratio := float64(withType) / float64(len(all))
		assert.Greater(t, ratio, 0.8,
			"only %d/%d findings have Resource Type populated", withType, len(all))
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

	t.Run("status distribution has all expected levels", func(t *testing.T) {
		counts := make(map[string]int)
		for _, rc := range all {
			counts[rc.Risk.Status]++
		}
		assert.Greater(t, counts["TH"], 0, "should have at least one high severity finding")
		assert.Greater(t, counts["TM"], 0, "should have at least one medium severity finding")
		assert.Greater(t, counts["TL"], 0, "should have at least one low severity finding")
	})
}
