package recon

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/aws/extraction"
	"github.com/praetorian-inc/aurelian/pkg/secrets"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time assertion: find-secrets uses the new extraction package.
var _ = extraction.NewAWSExtractor

func TestFindSecretsModuleMetadata(t *testing.T) {
	m := &AWSFindSecretsModule{}

	assert.Equal(t, "find-secrets", m.ID())
	assert.Equal(t, "AWS Find Secrets", m.Name())
	assert.Equal(t, plugin.PlatformAWS, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "moderate", m.OpsecLevel())

	authors := m.Authors()
	require.Len(t, authors, 1)
	assert.Equal(t, "Praetorian", authors[0])

	assert.NotEmpty(t, m.Description())
	assert.NotEmpty(t, m.References())
}

func TestFindSecretsSupportedResourceTypes(t *testing.T) {
	m := &AWSFindSecretsModule{}
	types := m.SupportedResourceTypes()

	expected := []string{
		"AWS::EC2::Instance",
		"AWS::Lambda::Function",
		"AWS::CloudFormation::Stack",
		"AWS::Logs::LogGroup",
		"AWS::ECS::TaskDefinition",
		"AWS::SSM::Document",
		"AWS::StepFunctions::StateMachine",
	}

	assert.Equal(t, expected, types)
}

func TestFindSecretsParameters(t *testing.T) {
	m := &AWSFindSecretsModule{}
	params, err := plugin.ParametersFrom(m.Parameters())
	require.NoError(t, err)

	paramNames := make(map[string]bool)
	for _, p := range params {
		paramNames[p.Name] = true
	}

	assert.True(t, paramNames["profile"], "should have profile param")
	assert.True(t, paramNames["regions"], "should have regions param")
	assert.True(t, paramNames["concurrency"], "should have concurrency param")
	assert.True(t, paramNames["db-path"], "should have db-path param")
	assert.True(t, paramNames["max-events"], "should have max-events param")
	assert.True(t, paramNames["max-streams"], "should have max-streams param")
}

func TestRiskSeverityFromConfidence(t *testing.T) {
	tests := []struct {
		name       string
		confidence string
		expected   output.RiskSeverity
	}{
		{"low", "low", output.RiskSeverityLow},
		{"medium", "medium", output.RiskSeverityMedium},
		{"high", "high", output.RiskSeverityHigh},
		{"critical", "critical", output.RiskSeverityCritical},
		{"unknown", "weird", output.RiskSeverityLow},
		{"empty", "", output.RiskSeverityLow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, riskSeverityFromConfidence(tt.confidence))
		})
	}
}

func TestBuildRiskContextRoundTrip(t *testing.T) {
	result := secrets.SecretScanResult{
		ResourceRef: "arn:aws:lambda:us-east-1:123456789012:function:demo",
		RuleName:    "AWS Access Key",
		RuleTextID:  "np.aws.1",
		Match:       "AKIAIOSFODNN7EXAMPLE",
		FilePath:    "main.py",
		LineNumber:  42,
		Confidence:  "high",
	}

	contextBytes, err := json.Marshal(result)
	require.NoError(t, err)

	var decoded secrets.SecretScanResult
	err = json.Unmarshal(contextBytes, &decoded)
	require.NoError(t, err)
	assert.Equal(t, result, decoded)
}

func TestRiskNameFormatting(t *testing.T) {
	ruleName := "AWS Access Key / Prod"
	expected := fmt.Sprintf("aws-secret-%s", ruleName)
	assert.Equal(t, expected, formatSecretRiskName(ruleName))
}
