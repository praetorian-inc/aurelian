//go:build integration

package recon

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/enrichers"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
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
			},
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
	require.NotEmpty(t, risks, "should emit at least one risk")

	for _, risk := range risks {
		assert.Equal(t, "public-aws-resource", risk.Name)
		assert.Equal(t, "aurelian", risk.Source)
		assert.Contains(t, []string{"TH", "TM"}, risk.Status)
		assert.NotEmpty(t, risk.TargetName)
		assert.NotEmpty(t, risk.Proof)
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
	}

	for _, expected := range expectedImpactedResources {
		assert.Truef(t, hasRiskForResource(risks, expected), "expected risk for resource %q", expected)
		t.Logf("found risk for resource %q", expected)
	}

	hasInvokeFunction := false
	hasInvokeFunctionURL := false
	hasAmplifyGetApp := false
	for _, risk := range risks {
		for _, action := range optionalSectionLabels(t, risk, "Allowed Actions") {
			switch action {
			case "lambda:InvokeFunction":
				hasInvokeFunction = true
			case "lambda:InvokeFunctionUrl":
				hasInvokeFunctionURL = true
			case "amplify:GetApp":
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
		assert.Equal(t, "TH", amplifyRisk.Status)
		assert.Contains(t, optionalSectionLabels(t, *amplifyRisk, "Allowed Actions"), "amplify:GetApp")
		reasons := optionalSectionLabels(t, *amplifyRisk, "Evaluation Reasons")
		require.NotEmpty(t, reasons)
		assert.Contains(t, reasons[0], "publicly accessible branch URL(s)")
	}

	publicAMIID := fixture.Output("public_ami_id")
	amiRisk := findRiskForResource(risks, publicAMIID)
	if assert.NotNilf(t, amiRisk, "expected risk for public AMI %s", publicAMIID) {
		assert.Contains(t, []string{"TH", "TM"}, amiRisk.Status)
		assert.Contains(t, optionalSectionLabels(t, *amiRisk, "Allowed Actions"), "ec2:RunInstances")
		assert.NotEmpty(t, optionalSectionLabels(t, *amiRisk, "Evaluation Reasons"))
	}

	t.Run("proof carries the standardized public-resource structure", func(t *testing.T) {
		proof := decodeProof(t, risks[0])
		assert.Equal(t, "v1.0.0", proof.Format)
		assert.NotEmpty(t, paragraphText(sectionByTitle(t, proof, "Summary")))
		resource := keyValueMap(sectionByTitle(t, proof, "Resource"))
		assert.Equal(t, risks[0].TargetName, resource["Resource ID"])
		assert.NotEmpty(t, keyValueMap(sectionByTitle(t, proof, "Exposure")))
	})
}

// optionalSectionLabels returns the list labels of a proof section when present,
// or nil when the section is absent (sectionByTitle fails on missing sections).
func optionalSectionLabels(t *testing.T, risk capmodel.Risk, title string) []string {
	t.Helper()
	proof := decodeProof(t, risk)
	for _, s := range proof.Sections {
		if s.Title == title {
			return listLabels(s)
		}
	}
	return nil
}

func findRiskForResource(risks []capmodel.Risk, expected string) *capmodel.Risk {
	for i := range risks {
		id := risks[i].TargetName
		if id == expected ||
			strings.HasSuffix(id, "/"+expected) ||
			strings.HasSuffix(id, ":"+expected) ||
			strings.Contains(id, expected) {
			return &risks[i]
		}
	}
	return nil
}

func hasRiskForResource(risks []capmodel.Risk, expected string) bool {
	for _, risk := range risks {
		id := risk.TargetName
		if id == expected ||
			strings.HasSuffix(id, "/"+expected) ||
			strings.HasSuffix(id, ":"+expected) {
			return true
		}
	}
	return false
}
