//go:build integration

package recon

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
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

	var risks []capmodel.Risk
	for m := range p2.Range() {
		r, ok := m.(capmodel.Risk)
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

	t.Run("all risks have a valid triage status", func(t *testing.T) {
		validStatuses := map[string]bool{"TI": true, "TL": true, "TM": true, "TH": true, "TC": true}
		for _, risk := range risks {
			assert.True(t, validStatuses[risk.Status],
				"unexpected status %q for risk %s", risk.Status, risk.Name)
		}
	})

	t.Run("all risks have a versioned proof with finding_id", func(t *testing.T) {
		for _, risk := range risks {
			require.NotEmpty(t, risk.Proof, "risk proof should not be empty for %s", risk.TargetName)
			var proof map[string]any
			require.NoError(t, json.Unmarshal(risk.Proof, &proof), "risk proof must be valid JSON")
			assert.Equal(t, "v1.0.0", proof["version"], "proof should carry the v1.0.0 schema version")
			assert.NotEmpty(t, proof["finding_id"], "proof should carry a non-empty finding_id")
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

	var risks []capmodel.Risk
	for m := range p2.Range() {
		r, ok := m.(capmodel.Risk)
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

	t.Run("status is medium for unvalidated secret", func(t *testing.T) {
		for _, risk := range risks {
			if risk.Name == "azure-secret-aws" {
				assert.Equal(t, "TM", risk.Status,
					"fake AWS key should be medium severity → TM (not validated)")
			}
		}
	})

	t.Run("only targeted VM resource has risks", func(t *testing.T) {
		for _, risk := range risks {
			assert.True(t, strings.Contains(strings.ToLower(risk.TargetName), strings.ToLower(vmID)),
				"risk TargetName %q should reference only the targeted VM, not other resources", risk.TargetName)
		}
	})

	t.Run("all risks have valid proof context", func(t *testing.T) {
		for _, risk := range risks {
			require.NotEmpty(t, risk.Proof, "risk proof should not be empty")
			var ctx map[string]interface{}
			require.NoError(t, json.Unmarshal(risk.Proof, &ctx), "risk proof must be valid JSON")
			assert.Equal(t, "v1.0.0", ctx["version"], "risk proof should carry the v1.0.0 schema version")
			assert.NotEmpty(t, ctx["rule_text_id"], "risk proof should have rule_text_id")
			assert.NotEmpty(t, ctx["resource_ref"], "risk proof should have resource_ref")
			assert.NotEmpty(t, ctx["matches"], "risk proof should have matches")
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
			require.NoError(t, json.Unmarshal(risk.Proof, &ctx))
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

	var risks []capmodel.Risk
	for m := range p2.Range() {
		r, ok := m.(capmodel.Risk)
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

// TestAzureFindSecretsResourcePolicyDefinition verifies that --resource-id works for
// subscription-scoped resources (no resourceGroups segment in the ID). Policy definitions
// are subscription-scoped and ARM-enumerated, exercising the arm.ParseResourceID path.
func TestAzureFindSecretsResourcePolicyDefinition(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/find-secrets")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAzure, plugin.CategoryRecon, "find-secrets")
	if !ok {
		t.Fatal("azure find-secrets module not registered in plugin system")
	}

	policyID := fixture.Output("policy_definition_id")
	require.NotEmpty(t, policyID, "fixture must provide policy_definition_id output")

	cfg := plugin.Config{
		Args: map[string]any{
			"resource-id": []string{policyID},
		},
		Context: context.Background(),
	}

	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	var risks []capmodel.Risk
	for m := range p2.Range() {
		r, ok := m.(capmodel.Risk)
		if !ok {
			continue
		}
		risks = append(risks, r)
	}
	require.NoError(t, p2.Wait())
	require.NotEmpty(t, risks, "expected at least one risk for policy definition resource")

	t.Run("only targeted policy definition has risks", func(t *testing.T) {
		for _, risk := range risks {
			assert.True(t, strings.Contains(strings.ToLower(risk.TargetName), strings.ToLower(policyID)),
				"risk TargetName %q should reference only the targeted policy definition", risk.TargetName)
		}
	})

	t.Run("all risks have a valid triage status", func(t *testing.T) {
		validStatuses := map[string]bool{"TI": true, "TL": true, "TM": true, "TH": true, "TC": true}
		for _, risk := range risks {
			assert.True(t, validStatuses[risk.Status],
				"unexpected status %q for risk %s", risk.Status, risk.Name)
		}
	})

	t.Run("all risks have valid proof context", func(t *testing.T) {
		for _, risk := range risks {
			require.NotEmpty(t, risk.Proof, "risk proof should not be empty")
			var ctx map[string]interface{}
			require.NoError(t, json.Unmarshal(risk.Proof, &ctx), "risk proof must be valid JSON")
			assert.Equal(t, "v1.0.0", ctx["version"], "risk proof should carry the v1.0.0 schema version")
			assert.NotEmpty(t, ctx["rule_text_id"], "risk proof should have rule_text_id")
			assert.NotEmpty(t, ctx["resource_ref"], "risk proof should have resource_ref")
			assert.NotEmpty(t, ctx["matches"], "risk proof should have matches")
		}
	})
}

// TestAzureFindSecretsResourceARMDeployment verifies --resource-id with a resource-group-scoped
// ARM deployment — a resource type discovered via ARM enumeration rather than ARG.
func TestAzureFindSecretsResourceARMDeployment(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/find-secrets")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAzure, plugin.CategoryRecon, "find-secrets")
	if !ok {
		t.Fatal("azure find-secrets module not registered in plugin system")
	}

	deploymentID := fixture.Output("arm_deployment_id")
	require.NotEmpty(t, deploymentID, "fixture must provide arm_deployment_id output")

	cfg := plugin.Config{
		Args: map[string]any{
			"resource-id": []string{deploymentID},
		},
		Context: context.Background(),
	}

	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	var risks []capmodel.Risk
	for m := range p2.Range() {
		r, ok := m.(capmodel.Risk)
		if !ok {
			continue
		}
		risks = append(risks, r)
	}
	require.NoError(t, p2.Wait())
	require.NotEmpty(t, risks, "expected at least one risk for ARM deployment resource")

	t.Run("only targeted deployment has risks", func(t *testing.T) {
		for _, risk := range risks {
			assert.True(t, strings.Contains(strings.ToLower(risk.TargetName), strings.ToLower(deploymentID)),
				"risk TargetName %q should reference only the targeted deployment", risk.TargetName)
		}
	})

	t.Run("all risks have valid proof context", func(t *testing.T) {
		for _, risk := range risks {
			require.NotEmpty(t, risk.Proof, "risk proof should not be empty")
			var ctx map[string]interface{}
			require.NoError(t, json.Unmarshal(risk.Proof, &ctx), "risk proof must be valid JSON")
			assert.Equal(t, "v1.0.0", ctx["version"], "risk proof should carry the v1.0.0 schema version")
			assert.NotEmpty(t, ctx["rule_text_id"], "risk proof should have rule_text_id")
			assert.NotEmpty(t, ctx["resource_ref"], "risk proof should have resource_ref")
		}
	})
}

// TestAzureFindSecretsResourceMixedScopes verifies --resource-id with a mix of
// resource-group-scoped (VM) and subscription-scoped (policy definition) resources
// in a single invocation.
func TestAzureFindSecretsResourceMixedScopes(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/find-secrets")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAzure, plugin.CategoryRecon, "find-secrets")
	if !ok {
		t.Fatal("azure find-secrets module not registered in plugin system")
	}

	vmID := fixture.Output("vm_id")
	policyID := fixture.Output("policy_definition_id")
	require.NotEmpty(t, vmID)
	require.NotEmpty(t, policyID)

	cfg := plugin.Config{
		Args: map[string]any{
			"resource-id": []string{vmID, policyID},
		},
		Context: context.Background(),
	}

	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	var risks []capmodel.Risk
	for m := range p2.Range() {
		r, ok := m.(capmodel.Risk)
		if !ok {
			continue
		}
		risks = append(risks, r)
	}
	require.NoError(t, p2.Wait())
	require.NotEmpty(t, risks, "expected risks from mixed-scope resource targeting")

	t.Run("detects secret in VM", func(t *testing.T) {
		assert.True(t, hasRiskForAzureResource(risks, vmID),
			"expected risk for VM %s", vmID)
	})

	t.Run("detects secret in policy definition", func(t *testing.T) {
		assert.True(t, hasRiskForAzureResource(risks, policyID),
			"expected risk for policy definition %s", policyID)
	})

	t.Run("all risks reference only targeted resources", func(t *testing.T) {
		lowerVM := strings.ToLower(vmID)
		lowerPolicy := strings.ToLower(policyID)
		for _, risk := range risks {
			lower := strings.ToLower(risk.TargetName)
			referencesVM := strings.Contains(lower, lowerVM)
			referencesPolicy := strings.Contains(lower, lowerPolicy)
			assert.True(t, referencesVM || referencesPolicy,
				"risk %q should reference one of the targeted resources, not leak to others", risk.TargetName)
		}
	})
}

func hasRiskForAzureResource(risks []capmodel.Risk, resourceID string) bool {
	lowerID := strings.ToLower(resourceID)
	for _, risk := range risks {
		lowerTarget := strings.ToLower(risk.TargetName)
		if lowerTarget == lowerID || strings.Contains(lowerTarget, lowerID) {
			return true
		}
	}
	return false
}
