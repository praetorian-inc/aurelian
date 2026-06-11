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

func TestAWSFindSecrets(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/find-secrets")
	fixture.Setup()

	// Log events expire with 1-day retention. Re-inject if missing so the
	// CloudWatch Logs subtest passes on long-lived fixtures.
	testutil.EnsureLogEvent(t, "us-east-2",
		fixture.Output("log_group_name"),
		fixture.Output("log_stream_name"),
		fixture.Output("log_event_message"),
	)

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

	var risks []capmodel.Risk
	for m := range p2.Range() {
		if r, ok := m.(capmodel.Risk); ok {
			risks = append(risks, r)
		}
	}
	require.NoError(t, p2.Wait())
	require.NotEmpty(t, risks, "expected at least one secret risk finding")

	// Map of resource type label → fixture output identifier to look for in TargetName.
	expectedResources := map[string]string{
		"EC2 Instance":    fixture.Output("instance_id"),
		"Lambda Function": fixture.Output("function_name"),
		"CloudFormation":  fixture.Output("stack_name"),
		"CloudWatch Logs": fixture.Output("log_group_name"),
		"ECS Task Def":    fixture.Output("task_definition_arn"),
		"SSM Document":    fixture.Output("ssm_document_name"),
		"SSM Parameter":   fixture.Output("ssm_parameter_name"),
		"Step Functions":  fixture.Output("state_machine_arn"),
	}

	for label, identifier := range expectedResources {
		t.Run("detects secret in "+label, func(t *testing.T) {
			found := hasRiskForIdentifier(risks, identifier)
			assert.True(t, found, "expected a risk referencing %s (%s)", label, identifier)
		})
	}

	t.Run("SecureString parameter is never scanned", func(t *testing.T) {
		secureName := fixture.Output("ssm_securestring_name")
		assert.False(t, hasRiskForIdentifier(risks, secureName),
			"SecureString parameter %q must not produce a risk finding", secureName)
	})

	t.Run("all risks have aws-secret- prefix", func(t *testing.T) {
		for _, risk := range risks {
			assert.True(t, strings.HasPrefix(risk.Name, "aws-secret-"),
				"risk name %q should start with aws-secret-", risk.Name)
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

func hasRiskForIdentifier(risks []capmodel.Risk, identifier string) bool {
	for _, risk := range risks {
		if risk.TargetName == identifier ||
			strings.Contains(risk.TargetName, identifier) {
			return true
		}
	}
	return false
}
