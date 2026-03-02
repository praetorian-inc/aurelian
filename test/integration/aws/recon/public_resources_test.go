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

	// Register modules and enrichers
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/enrichers"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon"
)

func TestPublicResources(t *testing.T) {
	fixture := testutil.NewFixture(t, "aws/recon/public-resources")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "public-resources")
	if !ok {
		t.Fatal("public-resources module not registered")
	}

	cfg := plugin.Config{
		Context: context.Background(),
		Args: map[string]any{
			"regions": []string{"us-east-1"},
		},
	}
	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	results, err := p2.Collect()
	require.NoError(t, err, "module run should succeed")
	require.NotEmpty(t, results, "expected at least one result")

	var risks []output.AurelianRisk
	for _, r := range results {
		if risk, ok := r.(output.AurelianRisk); ok {
			risks = append(risks, risk)
		}
	}
	require.NotEmpty(t, risks, "expected AurelianRisk output")

	for _, risk := range risks {
		assert.Equal(t, "public-aws-resource", risk.Name)
		assert.Contains(t, []output.RiskSeverity{output.RiskSeverityHigh, output.RiskSeverityMedium}, risk.Severity)
		assert.NotContains(t, string(risk.Context), "aws_resource")
		assert.NotEmpty(t, risk.ImpactedARN)
	}

	expectedImpactedResources := []string{
		fixture.Output("public_bucket_name"),
		fixture.Output("public_topic_arn"),
		fixture.Output("public_queue_name"),
		fixture.Output("public_function_name"),
		fixture.Output("lambda_policy_and_url_name"),
		fixture.Output("lambda_policy_only_name"),
		fixture.Output("public_instance_id"),
		fixture.Output("public_efs_id"),
		fixture.Output("public_cognito_pool_id"),
		fixture.Output("public_rds_identifier"),
	}

	for _, expected := range expectedImpactedResources {
		assert.Truef(t, hasRiskForResource(risks, expected), "expected risk for resource %q", expected)
	}

	hasInvokeFunction := false
	hasInvokeFunctionURL := false
	for _, risk := range risks {
		var ctx struct {
			AllowedActions []string `json:"allowed_actions"`
		}
		require.NoError(t, json.Unmarshal(risk.Context, &ctx))
		for _, action := range ctx.AllowedActions {
			if action == "lambda:InvokeFunction" {
				hasInvokeFunction = true
			}
			if action == "lambda:InvokeFunctionUrl" {
				hasInvokeFunctionURL = true
			}
		}
	}

	assert.True(t, hasInvokeFunction, "expected at least one risk with lambda:InvokeFunction")
	assert.True(t, hasInvokeFunctionURL, "expected at least one risk with lambda:InvokeFunctionUrl")

	testutil.AssertMinResults(t, results, 1)
}

func hasRiskForResource(risks []output.AurelianRisk, expected string) bool {
	for _, risk := range risks {
		if risk.ImpactedARN == expected {
			return true
		}
		if strings.Contains(risk.ImpactedARN, expected) {
			return true
		}
		if strings.HasSuffix(risk.ImpactedARN, "/"+expected) {
			return true
		}
		if strings.HasSuffix(risk.ImpactedARN, ":"+expected) {
			return true
		}
	}
	return false
}
