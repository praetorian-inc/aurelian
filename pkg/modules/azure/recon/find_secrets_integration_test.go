//go:build integration

package recon

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAzureFindSecrets(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/find-secrets")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAzure, plugin.CategoryRecon, "find-secrets")
	if !ok {
		t.Fatal("azure find-secrets module not registered in plugin system")
	}

	subscriptionID := fixture.Output("subscription_id")

	cfg := plugin.Config{
		Args: map[string]any{
			"subscription-ids": []string{subscriptionID},
			"scan-mode":        "all",
		},
		Context: context.Background(),
	}

	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	var risks []output.AurelianRisk
	for m := range p2.Range() {
		r, ok := m.(output.AurelianRisk)
		if !ok {
			continue
		}
		risks = append(risks, r)
	}
	require.NoError(t, p2.Wait())
	require.NotEmpty(t, risks, "expected at least one secret risk finding")

	expectedResources := map[string]string{
		// Original 6
		"VM":                 fixture.Output("vm_id"),
		"Web App":            fixture.Output("web_app_id"),
		"Automation Account": fixture.Output("automation_account_id"),
		"Storage Account":    fixture.Output("storage_account_id"),
		"Container Instance": fixture.Output("container_instance_id"),
		"Logic App":          fixture.Output("logic_app_id"),

		// Group A: enhanced existing resources
		"Function App": fixture.Output("function_app_id"),
		"App Config":   fixture.Output("app_config_id"),

		// Group B: IaC + VMSS
		"Template Spec": fixture.Output("template_spec_id"),
		"VMSS":          fixture.Output("vmss_id"),

		// IaC — ARM-enumerated (not discoverable via ARG Resources table)
		"ARM Deployment":    fixture.Output("arm_deployment_id"),
		"Policy Definition": fixture.Output("policy_definition_id"),

		// Group C: Container App, SWA, Batch, ACR
		"Container App":  fixture.Output("container_app_id"),
		"Static Web App": fixture.Output("static_web_app_id"),
		"Batch Account":  fixture.Output("batch_account_id"),
		"ACR":            fixture.Output("acr_id"),

		// Group D: Data, APIM
		"Data Factory":  fixture.Output("data_factory_id"),
		"Cosmos DB":     fixture.Output("cosmos_account_id"),
		"Digital Twins": fixture.Output("digital_twins_id"),
		"Synapse":       fixture.Output("synapse_workspace_id"),
		"APIM":          fixture.Output("apim_id"),
	}

	// App Insights may not trigger Titus (instrumentation key is a GUID, not a standard credential).
	// Log whether it was detected but don't fail the test on it.
	t.Run("app insights extractor runs", func(t *testing.T) {
		appInsightsID := fixture.Output("app_insights_id")
		found := hasRiskForAzureResource(risks, appInsightsID)
		t.Logf("App Insights detection: %v (resource: %s)", found, appInsightsID)
	})

	for label, resourceID := range expectedResources {
		t.Run("detects secret in "+label, func(t *testing.T) {
			found := hasRiskForAzureResource(risks, resourceID)
			assert.True(t, found, "expected a risk referencing %s (%s)", label, resourceID)
		})
	}

	t.Run("all risks have azure-secret- prefix", func(t *testing.T) {
		for _, risk := range risks {
			assert.True(t, strings.HasPrefix(risk.Name, "azure-secret-"),
				"risk name %q should start with azure-secret-", risk.Name)
		}
	})

	t.Run("all risks have severity set", func(t *testing.T) {
		validSeverities := map[output.RiskSeverity]bool{
			output.RiskSeverityLow:      true,
			output.RiskSeverityMedium:   true,
			output.RiskSeverityHigh:     true,
			output.RiskSeverityCritical: true,
		}
		for _, risk := range risks {
			assert.True(t, validSeverities[risk.Severity],
				"unexpected severity %q for risk %s", risk.Severity, risk.Name)
		}
	})

	t.Run("all risks have non-empty context", func(t *testing.T) {
		for _, risk := range risks {
			assert.NotEmpty(t, risk.Context, "risk context should not be empty for %s", risk.ImpactedResourceID)
		}
	})
}

func TestAzureFindSecretsResource(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/find-secrets")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAzure, plugin.CategoryRecon, "find-secrets")
	if !ok {
		t.Fatal("azure find-secrets module not registered in plugin system")
	}

	// Use the VM resource ID from the fixture — known to contain secrets.
	vmID := fixture.Output("vm_id")
	require.NotEmpty(t, vmID, "fixture must provide vm_id output")

	cfg := plugin.Config{
		Args: map[string]any{
			"resource-id": []string{vmID},
		},
		Context: context.Background(),
	}

	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	var risks []output.AurelianRisk
	for m := range p2.Range() {
		r, ok := m.(output.AurelianRisk)
		if !ok {
			continue
		}
		risks = append(risks, r)
	}
	require.NoError(t, p2.Wait())
	require.NotEmpty(t, risks, "expected at least one secret risk for VM resource")

	// The VM fixture plants a fake AWS key in user_data, so we expect:
	// - risk name: "azure-secret-aws"
	// - severity: medium (fake key won't pass validation)
	// - only the targeted VM resource referenced (no leakage from other resources)

	t.Run("detects planted AWS key with correct risk name", func(t *testing.T) {
		found := false
		for _, risk := range risks {
			if risk.Name == "azure-secret-aws" {
				found = true
				break
			}
		}
		assert.True(t, found, "expected risk named 'azure-secret-aws' from planted fake AWS key in VM user_data")
	})

	t.Run("severity is medium for unvalidated secret", func(t *testing.T) {
		for _, risk := range risks {
			if risk.Name == "azure-secret-aws" {
				assert.Equal(t, output.RiskSeverityMedium, risk.Severity,
					"fake AWS key should be medium severity (not validated)")
			}
		}
	})

	t.Run("only targeted VM resource has risks", func(t *testing.T) {
		for _, risk := range risks {
			assert.True(t, strings.Contains(strings.ToLower(risk.ImpactedResourceID), strings.ToLower(vmID)),
				"risk ImpactedResourceID %q should reference only the targeted VM, not other resources", risk.ImpactedResourceID)
		}
	})

	t.Run("all risks have valid proof context", func(t *testing.T) {
		for _, risk := range risks {
			require.NotEmpty(t, risk.Context, "risk context should not be empty")
			var ctx map[string]interface{}
			require.NoError(t, json.Unmarshal(risk.Context, &ctx), "risk context must be valid JSON")
			assert.NotEmpty(t, ctx["rule_text_id"], "risk context should have rule_text_id")
			assert.NotEmpty(t, ctx["resource_ref"], "risk context should have resource_ref")
			assert.NotEmpty(t, ctx["matches"], "risk context should have matches")
		}
	})

	t.Run("ARG hydration populates region in proof context", func(t *testing.T) {
		// The --resource-id path hydrates via ARG, so the proof context
		// should include a non-empty region (Location) from the VM resource.
		for _, risk := range risks {
			if risk.Name != "azure-secret-aws" {
				continue
			}
			var ctx map[string]interface{}
			require.NoError(t, json.Unmarshal(risk.Context, &ctx))
			matches, ok := ctx["matches"].([]interface{})
			if !ok || len(matches) == 0 {
				continue
			}
			match, ok := matches[0].(map[string]interface{})
			if !ok {
				continue
			}
			provenance, ok := match["provenance"].([]interface{})
			if !ok || len(provenance) == 0 {
				continue
			}
			prov, ok := provenance[0].(map[string]interface{})
			if !ok {
				continue
			}
			region, _ := prov["region"].(string)
			assert.NotEmpty(t, region, "ARG hydration should populate region (Location) for --resource-id path")
			return
		}
		t.Fatal("no azure-secret-aws risk found to check region")
	})
}

func TestAzureFindSecretsResourceMultiple(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/find-secrets")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAzure, plugin.CategoryRecon, "find-secrets")
	if !ok {
		t.Fatal("azure find-secrets module not registered in plugin system")
	}

	vmID := fixture.Output("vm_id")
	webAppID := fixture.Output("web_app_id")
	require.NotEmpty(t, vmID)
	require.NotEmpty(t, webAppID)

	cfg := plugin.Config{
		Args: map[string]any{
			"resource-id": []string{vmID, webAppID},
		},
		Context: context.Background(),
	}

	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	var risks []output.AurelianRisk
	for m := range p2.Range() {
		r, ok := m.(output.AurelianRisk)
		if !ok {
			continue
		}
		risks = append(risks, r)
	}
	require.NoError(t, p2.Wait())
	require.NotEmpty(t, risks, "expected risks from multiple targeted resources")

	foundVM := hasRiskForAzureResource(risks, vmID)
	foundWebApp := hasRiskForAzureResource(risks, webAppID)
	assert.True(t, foundVM, "expected risk for VM %s", vmID)
	assert.True(t, foundWebApp, "expected risk for Web App %s", webAppID)
}

func hasRiskForAzureResource(risks []output.AurelianRisk, resourceID string) bool {
	lowerID := strings.ToLower(resourceID)
	for _, risk := range risks {
		lowerImpacted := strings.ToLower(risk.ImpactedResourceID)
		if lowerImpacted == lowerID || strings.Contains(lowerImpacted, lowerID) {
			return true
		}
	}
	return false
}
