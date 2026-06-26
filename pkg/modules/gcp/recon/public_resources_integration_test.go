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

	resources, risks := runGCPPublicResources(t, mod, map[string]any{
		"project-id": []string{projectID},
		"resource-type": []string{
			"storage.googleapis.com/Bucket",
			"compute.googleapis.com/Instance",
			"sqladmin.googleapis.com/Instance",
			"cloudfunctions.googleapis.com/Function",
			"run.googleapis.com/Service",
			"compute.googleapis.com/Address",
			"compute.googleapis.com/GlobalAddress",
			"compute.googleapis.com/ForwardingRule",
		},
	})
	require.NotEmpty(t, risks, "should emit at least one risk for public resources")

	t.Run("risk fields are populated", func(t *testing.T) {
		for _, risk := range risks {
			assert.NotEmpty(t, risk.Name, "risk Name must be set")
			assert.Contains(t,
				[]output.RiskSeverity{output.RiskSeverityHigh, output.RiskSeverityMedium},
				risk.Severity,
				"unexpected risk severity: %s", risk.Severity)
			assert.NotEmpty(t, risk.ImpactedResourceID, "risk ImpactedResourceID must be set")
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

	t.Run("buckets have no risk without enricher", func(t *testing.T) {
		// No bucket enricher exists yet, so buckets don't get AnonymousAccess set
		// and BucketLister doesn't set IPs/URLs — no risk is generated.
		publicBucket := fixture.Output("public_bucket_name")
		privateBucket := fixture.Output("private_bucket_name")
		assert.Falsef(t, hasRiskForNamedResource(resources, risks, publicBucket),
			"public bucket %q should not have risk (no bucket enricher)", publicBucket)
		assert.Falsef(t, hasRiskForNamedResource(resources, risks, privateBucket),
			"private bucket %q should not have risk", privateBucket)
	})

	t.Run("detects public compute instance", func(t *testing.T) {
		instanceName := fixture.Output("instance_name")
		assert.Truef(t, hasRiskForNamedResource(resources, risks, instanceName),
			"expected risk for compute instance %q with external IP", instanceName)
	})

	t.Run("detects public sql instance", func(t *testing.T) {
		sqlName := fixture.Output("sql_instance_name")
		assert.Truef(t, hasRiskForNamedResource(resources, risks, sqlName),
			"expected risk for SQL instance %q with public IP", sqlName)
	})

	t.Run("detects public cloud function", func(t *testing.T) {
		functionName := fixture.Output("function_name")
		assert.Truef(t, hasRiskForNamedResource(resources, risks, functionName),
			"expected risk for cloud function %q with allUsers invoker", functionName)
	})

	t.Run("detects public cloud run services", func(t *testing.T) {
		publicRunName := fixture.Output("cloud_run_public_name")
		privateRunName := fixture.Output("cloud_run_private_name")

		// Public Cloud Run (allUsers invoker) should have HIGH severity (public + anonymous).
		assert.Truef(t, hasRiskForNamedResource(resources, risks, publicRunName),
			"expected risk for public cloud run service %q", publicRunName)

		// Private Cloud Run still gets a public URL from GCP, so it's flagged as
		// "public-gcp-resource" (MEDIUM). Both should have risks, but severity differs.
		publicRisk := findRiskForNamedResource(resources, risks, publicRunName)
		privateRisk := findRiskForNamedResource(resources, risks, privateRunName)
		if publicRisk != nil && privateRisk != nil {
			assert.Equal(t, output.RiskSeverityHigh, publicRisk.Severity,
				"public cloud run with allUsers should be HIGH")
			assert.Equal(t, output.RiskSeverityMedium, privateRisk.Severity,
				"private cloud run (URL only) should be MEDIUM")
		}
	})

	t.Run("detects public addresses", func(t *testing.T) {
		globalAddr := fixture.Output("global_address_name")
		regionalAddr := fixture.Output("regional_address_name")

		assert.Truef(t, hasRiskForNamedResource(resources, risks, globalAddr),
			"expected risk for global address %q", globalAddr)
		assert.Truef(t, hasRiskForNamedResource(resources, risks, regionalAddr),
			"expected risk for regional address %q", regionalAddr)
	})

	t.Run("private compute instance has no risk", func(t *testing.T) {
		privateInstance := fixture.Output("private_instance_name")
		assert.Falsef(t, hasRiskForNamedResource(resources, risks, privateInstance),
			"private compute instance %q should NOT have a risk", privateInstance)
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

	t.Run("direct resource mode detects public resources", func(t *testing.T) {
		zone := fixture.Output("instance_zone")
		region := gcpRegionFromZone(zone)
		cases := []struct {
			name         string
			resourceType string
			resourceID   string
			wantName     string
		}{
			{
				name:         "compute instance",
				resourceType: "compute.googleapis.com/Instance",
				resourceID:   "projects/" + projectID + "/zones/" + zone + "/instances/" + fixture.Output("instance_name"),
				wantName:     fixture.Output("instance_name"),
			},
			{
				name:         "sql instance",
				resourceType: "sqladmin.googleapis.com/Instance",
				resourceID:   fixture.Output("sql_instance_name"),
				wantName:     fixture.Output("sql_instance_name"),
			},
			{
				name:         "cloud function",
				resourceType: "cloudfunctions.googleapis.com/Function",
				resourceID:   "projects/" + projectID + "/locations/" + region + "/functions/" + fixture.Output("function_name"),
				wantName:     fixture.Output("function_name"),
			},
			{
				name:         "cloud run service",
				resourceType: "run.googleapis.com/Service",
				resourceID:   "projects/" + projectID + "/locations/" + region + "/services/" + fixture.Output("cloud_run_public_name"),
				wantName:     fixture.Output("cloud_run_public_name"),
			},
			{
				name:         "regional address",
				resourceType: "compute.googleapis.com/Address",
				resourceID:   "projects/" + projectID + "/regions/" + region + "/addresses/" + fixture.Output("regional_address_name"),
				wantName:     fixture.Output("regional_address_name"),
			},
			{
				name:         "global address",
				resourceType: "compute.googleapis.com/GlobalAddress",
				resourceID:   "projects/" + projectID + "/global/addresses/" + fixture.Output("global_address_name"),
				wantName:     fixture.Output("global_address_name"),
			},
			{
				name:         "regional forwarding rule",
				resourceType: "compute.googleapis.com/ForwardingRule",
				resourceID:   "projects/" + projectID + "/regions/" + region + "/forwardingRules/" + fixture.Output("regional_forwarding_rule_name"),
				wantName:     fixture.Output("regional_forwarding_rule_name"),
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				directResources, directRisks := runGCPPublicResources(t, mod, map[string]any{
					"project-id":    []string{projectID},
					"resource-type": []string{tc.resourceType},
					"resource-id":   []string{tc.resourceID},
				})
				require.NotEmpty(t, directResources, "expected direct scan resource for %s", tc.name)
				require.NotEmpty(t, directRisks, "expected direct scan risk for %s", tc.name)
				assert.True(t, hasRiskForNamedResource(directResources, directRisks, tc.wantName), "expected direct scan risk for %s", tc.wantName)
				for _, risk := range directRisks {
					assert.NotEmpty(t, risk.Context, "risk Context must be set")
				}
			})
		}
	})
}

func runGCPPublicResources(t *testing.T, mod plugin.Module, args map[string]any) ([]output.GCPResource, []output.AurelianRisk) {
	t.Helper()
	cfg := plugin.Config{
		Args:    args,
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
	return resources, risks
}

// hasRiskForNamedResource finds a resource by display name, then checks if
// there's a matching risk by ResourceID. This handles resources whose
// ResourceID is a numeric ID rather than a name.
func hasRiskForNamedResource(resources []output.GCPResource, risks []output.AurelianRisk, name string) bool {
	return findRiskForNamedResource(resources, risks, name) != nil
}

func findRiskForNamedResource(resources []output.GCPResource, risks []output.AurelianRisk, name string) *output.AurelianRisk {
	for _, r := range resources {
		if containsName(r, name) {
			for i, risk := range risks {
				if risk.ImpactedResourceID == r.ResourceID {
					return &risks[i]
				}
			}
			return nil
		}
	}
	return nil
}

func gcpRegionFromZone(zone string) string {
	parts := strings.Split(zone, "-")
	if len(parts) < 3 {
		return zone
	}
	return strings.Join(parts[:len(parts)-1], "-")
}
