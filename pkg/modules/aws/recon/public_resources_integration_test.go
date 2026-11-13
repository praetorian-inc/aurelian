//go:build integration

package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/enrichers"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	awsfixture "github.com/praetorian-inc/aurelian/test/testutil/fixture"
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

// TestAWSPublicResourcesByARN covers LAB-7805. Guard invokes public-resources
// in ARN mode exclusively, and every ARN service missing from the service map in
// pkg/types/enriched_resource_description.go failed the whole job before a single
// AWS call was made:
//
//	unsupported arn service "<service>"
//
// Production measured 34,941 such failures over 7 days across 35 tenants. The
// cases below are that measured failure set, plus the API Gateway v1/v2 pair,
// which resolved to the wrong type instead of failing outright.
//
// Type mode (TestAWSPublicResources) never caught any of this: it feeds the
// enumerator "AWS::..." type strings and so never resolves a type back from an
// ARN. Each case asserts the two things the by-ARN path has to get right — the
// job completes, and the resource is actually evaluated rather than silently
// skipped.
func TestAWSPublicResourcesByARN(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/public-resources")
	fixture.Setup()

	accountID, err := awsfixture.ResolveAWSAccountID(context.Background())
	require.NoError(t, err, "resolve aws account id")

	// arnFor builds the ARN Guard would pass for a fixture output. Outputs that
	// already hold a full ARN pass through unchanged.
	arnFor := func(format, value string) string {
		if value == "" || strings.HasPrefix(value, "arn:") {
			return value
		}
		return fmt.Sprintf(format, accountID, value)
	}

	cases := []struct {
		// service is the ARN service segment as it appears in the production
		// failure counts, for traceability back to the ticket.
		service string
		// output is the Terraform output naming the fixture resource. An empty
		// value means the fixture did not deploy it (var.deploy_expensive /
		// var.deploy_apprunner) and the case is skipped.
		output string
		arn    string
	}{
		{service: "elasticloadbalancing", output: "public_alb_arn", arn: "%[2]s"},
		{service: "cloudfront", output: "public_cloudfront_id", arn: "arn:aws:cloudfront::%s:distribution/%s"},
		{service: "efs", output: "public_efs_id", arn: "arn:aws:elasticfilesystem:us-east-1:%s:file-system/%s"},
		{service: "eks", output: "public_eks_arn", arn: "%[2]s"},
		{service: "appsync", output: "apikey_appsync_id", arn: "arn:aws:appsync:us-east-1:%s:apis/%s"},
		{service: "transfer", output: "public_transfer_id", arn: "arn:aws:transfer:us-east-1:%s:server/%s"},
		{service: "elasticbeanstalk", output: "public_beanstalk_env", arn: "%[2]s"},
		{service: "globalaccelerator", output: "public_ga_arn", arn: "%[2]s"},
		{service: "redshift", output: "public_redshift_identifier", arn: "arn:aws:redshift:us-east-1:%s:cluster:%s"},
		{service: "apprunner", output: "public_apprunner_arn", arn: "%[2]s"},
		{service: "apigateway/v1", output: "unauth_restapi_id", arn: "arn:aws:apigateway:us-east-1::/restapis/%[2]s"},
		{service: "apigateway/v2", output: "unauth_httpapi_id", arn: "arn:aws:apigateway:us-east-1::/apis/%[2]s"},
	}

	for _, tc := range cases {
		t.Run(tc.service, func(t *testing.T) {
			value := fixture.Output(tc.output)
			if value == "" {
				t.Skipf("fixture output %q is empty; resource not deployed in this account", tc.output)
			}

			resourceARN := arnFor(tc.arn, value)
			t.Logf("targeting %s", resourceARN)

			risks := runPublicResourcesByARN(t, resourceARN)

			risk := findRiskForResource(risks, value)
			require.NotNilf(t, risk,
				"expected a risk for %s resource %s; got %d risks. An empty result means the ARN "+
					"resolved but the evaluator skipped the type, which is the silent half of this bug",
				tc.service, value, len(risks))
			assert.Equal(t, "public-aws-resource", risk.Name)
			assert.NotEmpty(t, risk.ImpactedResourceID)
		})
	}
}

// runPublicResourcesByARN runs the module against a single ARN, exactly as Guard
// does, and returns the risks it emitted. A failure here is the bug: the module
// returned an error rather than a verdict.
func runPublicResourcesByARN(t *testing.T, resourceARN string) []output.AurelianRisk {
	t.Helper()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "public-resources")
	if !ok {
		t.Fatal("public-resources module not registered in plugin system")
	}

	cfg := plugin.Config{
		Args: map[string]any{
			// Global Accelerator's control plane is us-west-2; everything else
			// in the fixture is us-east-1.
			"regions":      []string{"us-east-1", "us-west-2"},
			"resource-arn": []string{resourceARN},
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
	require.NoErrorf(t, p2.Wait(), "ARN-mode run must not fail on %s", resourceARN)

	return risks
}

// TestAWSPublicResourcesCloudFrontByARN asserts the full verdict for the
// originally reported resource type, beyond the "job completes" check that
// TestAWSPublicResourcesByARN applies to every service: the risk must carry the
// distribution's own ARN and the evaluator's CloudFront reasoning.
func TestAWSPublicResourcesCloudFrontByARN(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/public-resources")
	fixture.Setup()

	accountID, err := awsfixture.ResolveAWSAccountID(context.Background())
	require.NoError(t, err, "resolve aws account id")

	distributionID := fixture.Output("public_cloudfront_id")
	distributionARN := fmt.Sprintf("arn:aws:cloudfront::%s:distribution/%s", accountID, distributionID)
	t.Logf("targeting %s", distributionARN)

	risks := runPublicResourcesByARN(t, distributionARN)

	risk := findRiskForResource(risks, distributionID)
	require.NotNilf(t, risk, "expected a risk for CloudFront distribution %s, got %d risks", distributionID, len(risks))

	assert.Equal(t, "public-aws-resource", risk.Name)
	assert.Equal(t, output.RiskSeverityMedium, risk.Severity,
		"an internet-facing distribution with no further signal is triage-worthy, not confirmed-high")
	assert.Equal(t, distributionARN, risk.ImpactedResourceID,
		"the risk must round-trip the ARN Guard passed in")

	var ctx struct {
		AllowedActions    []string `json:"allowed_actions"`
		EvaluationReasons []string `json:"evaluation_reasons"`
	}
	require.NoError(t, json.Unmarshal(risk.Context, &ctx))
	assert.Contains(t, ctx.AllowedActions, "cloudfront:NetworkAccess")
	require.NotEmpty(t, ctx.EvaluationReasons)
	assert.Contains(t, ctx.EvaluationReasons[0], "CloudFront distribution is internet-facing")
}
