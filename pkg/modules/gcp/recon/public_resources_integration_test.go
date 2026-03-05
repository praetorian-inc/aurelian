//go:build integration

package recon_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/gcp/enrichers"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGCPPublicResources(t *testing.T) {
	fixture := testutil.NewGCPFixture(t, "gcp/recon/list")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformGCP, plugin.CategoryRecon, "public-resources")
	if !ok {
		t.Fatal("gcp public-resources module not registered")
	}

	projectID := fixture.Output("project_id")

	cfg := plugin.Config{
		Args: map[string]any{
			"project-id": []string{projectID},
			"resource-type": []string{
				"storage.googleapis.com/Bucket",
				"compute.googleapis.com/Instance",
				"sqladmin.googleapis.com/Instance",
				"cloudfunctions.googleapis.com/Function",
			},
		},
		Context: context.Background(),
	}

	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	var resources []output.GCPResource
	var risks []output.AurelianRisk
	for m := range p2.Range() {
		switch v := m.(type) {
		case output.GCPResource:
			resources = append(resources, v)
		case output.AurelianRisk:
			risks = append(risks, v)
		}
	}
	require.NoError(t, p2.Wait())
	require.NotEmpty(t, risks, "should emit at least one risk for public resources")

	t.Run("risk fields are populated", func(t *testing.T) {
		for _, risk := range risks {
			assert.NotEmpty(t, risk.Name, "risk Name must be set")
			assert.Contains(t,
				[]output.RiskSeverity{output.RiskSeverityHigh, output.RiskSeverityMedium},
				risk.Severity,
				"unexpected risk severity: %s", risk.Severity)
			assert.NotEmpty(t, risk.ImpactedARN, "risk ImpactedARN must be set")
			assert.NotEmpty(t, risk.Context, "risk Context must be set")
		}
	})

	t.Run("risk context contains expected fields", func(t *testing.T) {
		for _, risk := range risks {
			var ctx map[string]any
			require.NoError(t, json.Unmarshal(risk.Context, &ctx))
			assert.Contains(t, ctx, "resourceType")
			assert.Contains(t, ctx, "resourceID")
			assert.Contains(t, ctx, "projectID")
			assert.Contains(t, ctx, "publicNetwork")
			assert.Contains(t, ctx, "anonymousAccess")
		}
	})

	t.Run("detects public storage bucket", func(t *testing.T) {
		publicBucket := fixture.Output("public_bucket_name")
		assert.Truef(t, hasRiskForGCPResource(risks, publicBucket),
			"expected risk for public bucket %q", publicBucket)

		privateBucket := fixture.Output("private_bucket_name")
		assert.Falsef(t, hasRiskForGCPResource(risks, privateBucket),
			"private bucket %q should NOT have a risk", privateBucket)
	})

	t.Run("detects public compute instance", func(t *testing.T) {
		instanceName := fixture.Output("instance_name")
		assert.Truef(t, hasRiskForGCPResource(risks, instanceName),
			"expected risk for compute instance %q with external IP", instanceName)
	})

	t.Run("detects public sql instance", func(t *testing.T) {
		sqlName := fixture.Output("sql_instance_name")
		assert.Truef(t, hasRiskForGCPResource(risks, sqlName),
			"expected risk for SQL instance %q with public IP", sqlName)
	})

	t.Run("detects public cloud function", func(t *testing.T) {
		functionName := fixture.Output("function_name")
		assert.Truef(t, hasRiskForGCPResource(risks, functionName),
			"expected risk for cloud function %q with allUsers invoker", functionName)
	})

	t.Run("risk names follow gcp naming convention", func(t *testing.T) {
		validNames := map[string]bool{
			"public-anonymous-gcp-resource": true,
			"anonymous-gcp-resource":        true,
			"public-gcp-resource":           true,
		}
		for _, risk := range risks {
			assert.Truef(t, validNames[risk.Name],
				"unexpected risk name %q", risk.Name)
		}
	})
}

func hasRiskForGCPResource(risks []output.AurelianRisk, name string) bool {
	for _, risk := range risks {
		if strings.Contains(risk.ImpactedARN, name) {
			return true
		}
	}
	return false
}
