//go:build integration

package recon

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/enrichers"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAWSPublicResources(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/public-resources")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "public-resources")
	if !ok {
		t.Fatal("public-resources module not registered in plugin system")
	}

	cfg := plugin.Config{
		Args: map[string]any{
			"regions": []string{"us-east-1"},
			"resource-type": []string{
				"AWS::S3::Bucket",
				"AWS::SNS::Topic",
				"AWS::SQS::Queue",
				"AWS::Lambda::Function",
				"AWS::EC2::Instance",
				"AWS::EFS::FileSystem",
				"AWS::Cognito::UserPool",
				"AWS::RDS::DBInstance",
				"AWS::EC2::Image",
			},
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
	require.NotEmpty(t, risks, "should emit at least one risk")

	for _, risk := range risks {
		assert.True(t, strings.HasPrefix(risk.Name, "public-aws-resource-"),
			"risk name %q should have prefix public-aws-resource-", risk.Name)
		assert.NotEmpty(t, risk.DeduplicationID, "risk should have DeduplicationID set to resource type")
		assert.Contains(t, []output.RiskSeverity{output.RiskSeverityHigh, output.RiskSeverityMedium}, risk.Severity)
		assert.NotContains(t, string(risk.Context), "aws_resource")
		assert.NotEmpty(t, risk.ImpactedResourceID)
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
		fixture.Output("public_ami_id"),
	}

	for _, expected := range expectedImpactedResources {
		assert.Truef(t, hasRiskForResource(risks, expected), "expected risk for resource %q", expected)
		t.Logf("found risk for resource %q", expected)
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

	publicAMIID := fixture.Output("public_ami_id")
	amiRisk := findRiskForResource(risks, publicAMIID)
	if assert.NotNilf(t, amiRisk, "expected risk for public AMI %s", publicAMIID) {
		assert.Contains(t, []output.RiskSeverity{output.RiskSeverityHigh, output.RiskSeverityMedium}, amiRisk.Severity)
		var ctx struct {
			AllowedActions    []string `json:"allowed_actions"`
			EvaluationReasons []string `json:"evaluation_reasons"`
		}
		require.NoError(t, json.Unmarshal(amiRisk.Context, &ctx))
		assert.Contains(t, ctx.AllowedActions, "ec2:RunInstances")
		assert.NotEmpty(t, ctx.EvaluationReasons)
	}
}

func findRiskForResource(risks []output.AurelianRisk, expected string) *output.AurelianRisk {
	for _, risk := range risks {
		if risk.ImpactedResourceID == expected ||
			strings.HasSuffix(risk.ImpactedResourceID, "/"+expected) ||
			strings.HasSuffix(risk.ImpactedResourceID, ":"+expected) ||
			strings.Contains(risk.ImpactedResourceID, expected) {
			return &risk
		}
	}
	return nil
}

func hasRiskForResource(risks []output.AurelianRisk, expected string) bool {
	for _, risk := range risks {
		if risk.ImpactedResourceID == expected {
			return true
		}
		if strings.HasSuffix(risk.ImpactedResourceID, "/"+expected) {
			return true
		}
		if strings.HasSuffix(risk.ImpactedResourceID, ":"+expected) {
			return true
		}
	}
	return false
}
