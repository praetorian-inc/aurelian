//go:build integration

package recon

import (
	"context"
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
			"subscription-id": []string{subscriptionID},
			"scan-mode":       "all",
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
		"VM":                 fixture.Output("vm_id"),
		"Web App":            fixture.Output("web_app_id"),
		"Automation Account": fixture.Output("automation_account_id"),
		"Storage Account":    fixture.Output("storage_account_id"),
	}

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
			assert.NotEmpty(t, risk.Context, "risk context should not be empty for %s", risk.ImpactedARN)
		}
	})
}

func hasRiskForAzureResource(risks []output.AurelianRisk, resourceID string) bool {
	lowerID := strings.ToLower(resourceID)
	for _, risk := range risks {
		lowerImpacted := strings.ToLower(risk.ImpactedARN)
		if lowerImpacted == lowerID || strings.Contains(lowerImpacted, lowerID) {
			return true
		}
	}
	return false
}
