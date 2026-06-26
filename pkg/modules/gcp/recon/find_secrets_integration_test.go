//go:build integration

package recon_test

import (
	"context"
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

func TestGCPFindSecrets(t *testing.T) {
	fixture := testutil.NewGCPFixture(t, "gcp/recon/find-secrets")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformGCP, plugin.CategoryRecon, "find-secrets")
	if !ok {
		t.Fatal("find-secrets module not registered in plugin system")
	}

	projectID := fixture.Output("project_id")

	risks := runGCPFindSecrets(t, mod, map[string]any{
		"project-id": []string{projectID},
	})
	require.NotEmpty(t, risks, "expected at least one secret risk finding")

	// Cloud Function ResourceIDs contain the full resource path including the function name.
	t.Run("detects secret in Cloud Function", func(t *testing.T) {
		functionName := fixture.Output("function_name")
		found := hasGCPRiskForIdentifier(risks, functionName)
		assert.True(t, found, "expected a risk referencing Cloud Function %s", functionName)
	})

	t.Run("detects secret in Compute Instance", func(t *testing.T) {
		instanceName := fixture.Output("instance_name")
		found := hasGCPRiskForIdentifier(risks, instanceName)
		assert.True(t, found, "expected a risk referencing Compute Instance %s", instanceName)
	})

	t.Run("detects secret in Storage Bucket", func(t *testing.T) {
		bucketName := fixture.Output("bucket_name")
		found := hasGCPRiskForIdentifier(risks, bucketName)
		assert.True(t, found, "expected a risk referencing Storage Bucket %s", bucketName)
	})

	// Cloud Run ResourceIDs contain the full resource path including the service name.
	t.Run("detects secret in Cloud Run Service", func(t *testing.T) {
		serviceName := fixture.Output("cloud_run_service_name")
		found := hasGCPRiskForIdentifier(risks, serviceName)
		assert.True(t, found, "expected a risk referencing Cloud Run Service %s", serviceName)
	})

	t.Run("all risks have gcp-secret- prefix", func(t *testing.T) {
		for _, risk := range risks {
			assert.True(t, strings.HasPrefix(risk.Name, "gcp-secret-"),
				"risk name %q should start with gcp-secret-", risk.Name)
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

	t.Run("direct resource mode detects secrets", func(t *testing.T) {
		region := fixture.Output("region")
		zone := fixture.Output("zone")
		cases := []struct {
			name         string
			resourceType string
			resourceID   string
			wantID       string
		}{
			{
				name:         "compute instance",
				resourceType: "compute.googleapis.com/Instance",
				resourceID:   "projects/" + projectID + "/zones/" + zone + "/instances/" + fixture.Output("instance_name"),
				wantID:       fixture.Output("instance_name"),
			},
			{
				name:         "cloud function",
				resourceType: "cloudfunctions.googleapis.com/Function",
				resourceID:   "projects/" + projectID + "/locations/" + region + "/functions/" + fixture.Output("function_name"),
				wantID:       fixture.Output("function_name"),
			},
			{
				name:         "cloud run service",
				resourceType: "run.googleapis.com/Service",
				resourceID:   "projects/" + projectID + "/locations/" + region + "/services/" + fixture.Output("cloud_run_service_name"),
				wantID:       fixture.Output("cloud_run_service_name"),
			},
			{
				name:         "storage bucket",
				resourceType: "storage.googleapis.com/Bucket",
				resourceID:   fixture.Output("bucket_name"),
				wantID:       fixture.Output("bucket_name"),
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				directRisks := runGCPFindSecrets(t, mod, map[string]any{
					"project-id":    []string{projectID},
					"resource-type": []string{tc.resourceType},
					"resource-id":   []string{tc.resourceID},
				})
				require.NotEmpty(t, directRisks, "expected direct scan risk for %s", tc.name)
				assert.True(t, hasGCPRiskForIdentifier(directRisks, tc.wantID), "expected direct scan risk referencing %s", tc.wantID)
				for _, risk := range directRisks {
					assert.True(t, strings.HasPrefix(risk.Name, "gcp-secret-"), "risk name %q should start with gcp-secret-", risk.Name)
					assert.NotEmpty(t, risk.Context, "risk context should not be empty for %s", risk.ImpactedResourceID)
				}
			})
		}
	})
}

func runGCPFindSecrets(t *testing.T, mod plugin.Module, args map[string]any) []output.AurelianRisk {
	t.Helper()
	cfg := plugin.Config{
		Args:    args,
		Context: context.Background(),
	}

	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	var risks []output.AurelianRisk
	for m := range p2.Range() {
		if r, ok := m.(output.AurelianRisk); ok {
			risks = append(risks, r)
		}
	}
	require.NoError(t, p2.Wait())
	return risks
}

func hasGCPRiskForIdentifier(risks []output.AurelianRisk, identifier string) bool {
	for _, risk := range risks {
		if strings.Contains(risk.ImpactedResourceID, identifier) {
			return true
		}
	}
	return false
}
