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
				"AWS::Amplify::App",
				"AWS::S3::Bucket",
				"AWS::SNS::Topic",
				"AWS::SQS::Queue",
				"AWS::Lambda::Function",
				"AWS::EC2::Instance",
				"AWS::EFS::FileSystem",
				"AWS::Cognito::UserPool",
				"AWS::RDS::DBInstance",
				"AWS::EC2::Image",
				// Application ingress layer (feat/public-resources-ingress).
				// Enumerated and evaluated on a live run. Full fixture-backed
				// assertions require the Terraform resources noted in the TODO below.
				"AWS::ElasticLoadBalancingV2::LoadBalancer",
				"AWS::ElasticLoadBalancing::LoadBalancer",
				"AWS::AppRunner::Service",
				"AWS::CloudFront::Distribution",
				"AWS::GlobalAccelerator::Accelerator",
				"AWS::ElasticBeanstalk::Environment",
				"AWS::Transfer::Server",
				"AWS::AppSync::GraphQLApi",
				"AWS::OpenSearchService::Domain",
				"AWS::EKS::Cluster",
				"AWS::ApiGateway::RestApi",
				"AWS::ApiGatewayV2::Api",
			},
		},
		Context: context.Background(),
	}

	// The ingress cheap tranche (always deployed) is asserted below. The
	// expensive fixtures (EKS, FGAC-off OpenSearch, Beanstalk) deploy only when
	// the fixture is applied with -var deploy_expensive=true; their outputs are
	// empty otherwise, so they are asserted separately further down.

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
		assert.Equal(t, "public-aws-resource", risk.Name)
		assert.Contains(t, []output.RiskSeverity{output.RiskSeverityHigh, output.RiskSeverityMedium}, risk.Severity)
		assert.NotContains(t, string(risk.Context), "aws_resource")
		assert.NotEmpty(t, risk.ImpactedResourceID)
	}

	expectedImpactedResources := []string{
		fixture.Output("public_amplify_app_id"),
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
		// Application ingress layer — cheap tranche (always deployed).
		fixture.Output("public_alb_arn"),
		fixture.Output("public_apprunner_arn"),
		fixture.Output("public_cloudfront_id"),
		fixture.Output("public_ga_arn"),
		fixture.Output("public_transfer_id"),
		fixture.Output("apikey_appsync_id"),
		fixture.Output("unauth_restapi_id"),
		fixture.Output("unauth_httpapi_id"),
		// Recently-changed branches that still flag (edge positives): a REST API
		// gated by a resource policy is reported for triage, and an additional
		// API_KEY provider on a non-API_KEY AppSync API is reported.
		fixture.Output("policy_restapi_id"),
		fixture.Output("additional_apikey_appsync_id"),
	}

	for _, expected := range expectedImpactedResources {
		assert.Truef(t, hasRiskForResource(risks, expected), "expected risk for resource %q", expected)
		t.Logf("found risk for resource %q", expected)
	}

	// Negative controls: these must NOT be flagged. private_restapi_id is a
	// PRIVATE REST API whose NONE-auth method is not internet-exposed.
	for _, name := range []string{"internal_alb_arn", "iam_appsync_id", "private_restapi_id"} {
		id := fixture.Output(name)
		assert.Falsef(t, hasRiskForResource(risks, id), "internal/authenticated resource %q (%s) must not be flagged", id, name)
	}

	// Expensive tranche positives: only asserted when deployed (outputs are empty otherwise).
	for _, name := range []string{"public_eks_arn", "no_fgac_domain", "public_beanstalk_env"} {
		if id := fixture.Output(name); id != "" {
			assert.Truef(t, hasRiskForResource(risks, id), "expected risk for expensive resource %q (%s)", id, name)
		}
	}

	// Expensive tranche negatives: a FGAC-off domain with a policy scoped to a
	// specific principal (not a wildcard) must NOT be flagged. Only asserted when deployed.
	for _, name := range []string{"restrictive_nofgac_domain"} {
		if id := fixture.Output(name); id != "" {
			assert.Falsef(t, hasRiskForResource(risks, id), "FGAC-off restrictive-policy resource %q (%s) must not be flagged", id, name)
		}
	}

	hasInvokeFunction := false
	hasInvokeFunctionURL := false
	hasAmplifyGetApp := false
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
			if action == "amplify:GetApp" {
				hasAmplifyGetApp = true
			}
		}
	}

	assert.True(t, hasInvokeFunction, "expected at least one risk with lambda:InvokeFunction")
	assert.True(t, hasInvokeFunctionURL, "expected at least one risk with lambda:InvokeFunctionUrl")
	assert.True(t, hasAmplifyGetApp, "expected at least one risk with amplify:GetApp")

	amplifyAppID := fixture.Output("public_amplify_app_id")
	amplifyRisk := findRiskForResource(risks, amplifyAppID)
	if assert.NotNilf(t, amplifyRisk, "expected risk for Amplify app %s", amplifyAppID) {
		assert.Equal(t, output.RiskSeverityHigh, amplifyRisk.Severity)
		var ctx struct {
			AllowedActions    []string `json:"allowed_actions"`
			EvaluationReasons []string `json:"evaluation_reasons"`
		}
		require.NoError(t, json.Unmarshal(amplifyRisk.Context, &ctx))
		assert.Contains(t, ctx.AllowedActions, "amplify:GetApp")
		assert.NotEmpty(t, ctx.EvaluationReasons)
		assert.Contains(t, ctx.EvaluationReasons[0], "publicly accessible branch URL(s)")
	}

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
