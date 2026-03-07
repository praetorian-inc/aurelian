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

	cfg := plugin.Config{
		Args: map[string]any{
			"project-id": []string{projectID},
		},
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
	require.NotEmpty(t, risks, "expected at least one secret risk finding")

	// Cloud Function ResourceIDs contain the full resource path including the function name.
	t.Run("detects secret in Cloud Function", func(t *testing.T) {
		functionName := fixture.Output("function_name")
		found := hasGCPRiskForIdentifier(risks, functionName)
		assert.True(t, found, "expected a risk referencing Cloud Function %s", functionName)
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
			assert.NotEmpty(t, risk.Context, "risk context should not be empty for %s", risk.ImpactedARN)
		}
	})
}

func hasGCPRiskForIdentifier(risks []output.AurelianRisk, identifier string) bool {
	for _, risk := range risks {
		if strings.Contains(risk.ImpactedARN, identifier) {
			return true
		}
	}
	return false
}
