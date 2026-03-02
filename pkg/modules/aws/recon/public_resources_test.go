package recon

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/aws/publicaccess"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicResourcesModuleMetadata(t *testing.T) {
	m := &AWSPublicResourcesModule{}

	assert.Equal(t, "public-resources", m.ID())
	assert.Equal(t, "AWS Public Resources", m.Name())
	assert.Equal(t, plugin.PlatformAWS, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "moderate", m.OpsecLevel())

	authors := m.Authors()
	require.Len(t, authors, 1)
	assert.Equal(t, "Praetorian", authors[0])

	assert.NotEmpty(t, m.Description())
	assert.NotEmpty(t, m.References())
}

func TestPublicResourcesSupportedResourceTypes(t *testing.T) {
	m := &AWSPublicResourcesModule{}
	types := m.SupportedResourceTypes()

	expected := []string{
		"AWS::EC2::Instance",
		"AWS::S3::Bucket",
		"AWS::SNS::Topic",
		"AWS::SQS::Queue",
		"AWS::Lambda::Function",
		"AWS::EFS::FileSystem",
		"AWS::Cognito::UserPool",
		"AWS::RDS::DBInstance",
	}

	assert.Equal(t, expected, types)
	assert.Len(t, types, 8)
}

func TestPublicResourcesParameters(t *testing.T) {
	m := &AWSPublicResourcesModule{}
	params, err := plugin.ParametersFrom(m.Parameters())
	require.NoError(t, err)

	paramNames := make(map[string]bool)
	for _, p := range params {
		paramNames[p.Name] = true
	}

	// Must include AWS params from AWSCommonRecon
	assert.True(t, paramNames["profile"], "should have profile param")
	assert.True(t, paramNames["regions"], "should have regions param")
	assert.True(t, paramNames["concurrency"], "should have concurrency param")

	// Must include resource-id and resource-type params
	assert.True(t, paramNames["resource-id"], "should have resource-id param")
	assert.True(t, paramNames["resource-type"], "should have resource-type param")

	// Must include org-policies param
	assert.True(t, paramNames["org-policies"], "should have org-policies param")
}

func TestRiskFromResult_Public(t *testing.T) {
	risk, ok, err := riskFromResult(publicaccess.PublicAccessResult{
		AWSResource: &output.AWSResource{AccessLevel: output.AccessLevelPublic, ResourceID: "example-bucket", ARN: "arn:aws:s3:::example-bucket"},
		IsPublic:    true,
	})
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, risk)
	assert.Equal(t, output.RiskSeverityHigh, risk.Severity)
	assert.Equal(t, "public-aws-resource", risk.Name)
	assert.Equal(t, "arn:aws:s3:::example-bucket", risk.ImpactedARN)
	assert.NotContains(t, string(risk.Context), "aws_resource")
}

func TestRiskFromResult_NeedsTriage(t *testing.T) {
	risk, ok, err := riskFromResult(publicaccess.PublicAccessResult{
		AWSResource:       &output.AWSResource{AccessLevel: output.AccessLevelNeedsTriage, ResourceID: "fn-name"},
		IsPublic:          true,
		NeedsManualTriage: true,
	})
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, risk)
	assert.Equal(t, output.RiskSeverityMedium, risk.Severity)
	assert.Equal(t, "fn-name", risk.ImpactedARN)

	var ctx map[string]any
	require.NoError(t, json.Unmarshal(risk.Context, &ctx))
	assert.Equal(t, true, ctx["needs_manual_triage"])
}

func TestRiskFromResult_PrivateFiltered(t *testing.T) {
	risk, ok, err := riskFromResult(publicaccess.PublicAccessResult{
		AWSResource: &output.AWSResource{AccessLevel: output.AccessLevelPrivate},
	})
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Nil(t, risk)
}
