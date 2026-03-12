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

func TestAWSFindSecrets(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/find-secrets")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "find-secrets")
	if !ok {
		t.Fatal("find-secrets module not registered in plugin system")
	}

	// Run against all supported resource types.
	cfg := plugin.Config{
		Args: map[string]any{
			"regions":     []string{"us-east-2"},
			"max-events":  10000,
			"max-streams": 10,
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

	// Map of resource type label → fixture output identifier to look for in ImpactedResourceID.
	expectedResources := map[string]string{
		"EC2 Instance":       fixture.Output("instance_id"),
		"Lambda Function":    fixture.Output("function_name"),
		"CloudFormation":     fixture.Output("stack_name"),
		"CloudWatch Logs":    fixture.Output("log_group_name"),
		"ECS Task Def":       fixture.Output("task_definition_arn"),
		"SSM Document":       fixture.Output("ssm_document_name"),
		"Step Functions":     fixture.Output("state_machine_arn"),
	}

	for label, identifier := range expectedResources {
		t.Run("detects secret in "+label, func(t *testing.T) {
			found := hasRiskForIdentifier(risks, identifier)
			assert.True(t, found, "expected a risk referencing %s (%s)", label, identifier)
		})
	}

	t.Run("all risks have aws-secret- prefix", func(t *testing.T) {
		for _, risk := range risks {
			assert.True(t, strings.HasPrefix(risk.Name, "aws-secret-"),
				"risk name %q should start with aws-secret-", risk.Name)
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

func hasRiskForIdentifier(risks []output.AurelianRisk, identifier string) bool {
	for _, risk := range risks {
		if risk.ImpactedResourceID == identifier ||
			strings.Contains(risk.ImpactedResourceID, identifier) {
			return true
		}
	}
	return false
}
