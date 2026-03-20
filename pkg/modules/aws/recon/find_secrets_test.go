package recon

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/aws/extraction"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/secrets"
	"github.com/praetorian-inc/titus/pkg/types"
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

func TestExtractRuleShortName(t *testing.T) {
	tests := []struct {
		ruleID   string
		expected string
	}{
		{"np.aws.1", "aws"},
		{"np.github.2", "github"},
		{"np.generic.3", "generic"},
		{"singleword", "singleword"},
	}
	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			assert.Equal(t, tt.expected, secrets.ExtractRuleShortName(tt.ruleID))
		})
	}
}

func TestRiskNameFormatting(t *testing.T) {
	tests := []struct {
		ruleID   string
		expected string
	}{
		{"np.aws.1", "aws-secret-aws"},
		{"np.github.2", "aws-secret-github"},
		{"np.generic.3", "aws-secret-generic"},
		{"singleword", "aws-secret-singleword"},
	}
	for _, tt := range tests {
		t.Run(tt.ruleID, func(t *testing.T) {
			assert.Equal(t, tt.expected, fmt.Sprintf("aws-secret-%s", secrets.ExtractRuleShortName(tt.ruleID)))
		})
	}
}

func TestRiskSeverityFromMatch(t *testing.T) {
	t.Run("validated secret returns high", func(t *testing.T) {
		match := &types.Match{
			ValidationResult: &types.ValidationResult{Status: types.StatusValid},
		}
		assert.Equal(t, output.RiskSeverityHigh, secrets.RiskSeverityFromMatch(match))
	})

	t.Run("no validation returns medium", func(t *testing.T) {
		match := &types.Match{}
		assert.Equal(t, output.RiskSeverityMedium, secrets.RiskSeverityFromMatch(match))
	})

	t.Run("invalid validation returns medium", func(t *testing.T) {
		match := &types.Match{
			ValidationResult: &types.ValidationResult{Status: types.StatusInvalid},
		}
		assert.Equal(t, output.RiskSeverityMedium, secrets.RiskSeverityFromMatch(match))
	})
}

func TestToRisk_ProofData(t *testing.T) {
	match := &types.Match{
		RuleID:    "np.aws.1",
		RuleName:  "AWS API Key",
		FindingID: "abc123def456",
		Snippet: types.Snippet{
			Before:   []byte("key="),
			Matching: []byte("AKIAIOSFODNN7EXAMPLE"),
			After:    []byte("\n"),
		},
		Location: types.Location{
			Offset: types.OffsetSpan{Start: 4, End: 24},
			Source: types.SourceSpan{
				Start: types.SourcePoint{Line: 1, Column: 5},
				End:   types.SourcePoint{Line: 1, Column: 25},
			},
		},
	}

	result := secrets.SecretScanResult{
		ResourceRef:  "arn:aws:lambda:us-east-1:123:function:demo",
		ResourceType: "AWS::Lambda::Function",
		Region:       "us-east-1",
		AccountID:    "123",
		Platform:     "aws",
		Label:        "handler.py",
		Match:        match,
	}

	risk, err := result.ToRisk()
	require.NoError(t, err)

	var proof map[string]any
	require.NoError(t, json.Unmarshal(risk.Context, &proof))

	assert.Equal(t, "abc123def456", proof["finding_id"])
	assert.Equal(t, "AWS API Key", proof["rule_name"])
	assert.Equal(t, "np.aws.1", proof["rule_text_id"])
	assert.Equal(t, "arn:aws:lambda:us-east-1:123:function:demo", proof["resource_ref"])
	assert.Equal(t, float64(1), proof["num_matches"])

	matches := proof["matches"].([]any)
	require.Len(t, matches, 1)

	m0 := matches[0].(map[string]any)
	snippet := m0["snippet"].(map[string]any)
	assert.Equal(t, "key=", snippet["before"])
	assert.Equal(t, "AKIAIOSFODNN7EXAMPLE", snippet["matching"])
	assert.Equal(t, "\n", snippet["after"])

	location := m0["location"].(map[string]any)
	offsetSpan := location["offset_span"].(map[string]any)
	assert.Equal(t, float64(4), offsetSpan["start"])
	assert.Equal(t, float64(24), offsetSpan["end"])

	sourceSpan := location["source_span"].(map[string]any)
	start := sourceSpan["start"].(map[string]any)
	assert.Equal(t, float64(1), start["line"])
	assert.Equal(t, float64(5), start["column"])

	provenance := m0["provenance"].([]any)
	require.Len(t, provenance, 1)
	prov := provenance[0].(map[string]any)
	assert.Equal(t, "cloud", prov["kind"])
	assert.Equal(t, "aws", prov["platform"])
	assert.Equal(t, "arn:aws:lambda:us-east-1:123:function:demo", prov["resource_id"])
	assert.Equal(t, "AWS::Lambda::Function", prov["resource_type"])

	_, hasValidation := proof["validation"]
	assert.False(t, hasValidation, "no validation when ValidationResult is nil")
}

func TestToRisk_WithValidation(t *testing.T) {
	match := &types.Match{
		RuleID:    "np.aws.1",
		RuleName:  "AWS API Key",
		FindingID: "abc123",
		ValidationResult: &types.ValidationResult{
			Status:     types.StatusValid,
			Confidence: 0.95,
			Message:    "Key is active",
		},
	}

	result := secrets.SecretScanResult{
		ResourceRef:  "arn:aws:s3:::bucket",
		ResourceType: "AWS::S3::Bucket",
		Platform:     "aws",
		Label:        "config.yaml",
		Match:        match,
	}

	risk, err := result.ToRisk()
	require.NoError(t, err)

	var proof map[string]any
	require.NoError(t, json.Unmarshal(risk.Context, &proof))

	validation := proof["validation"].(map[string]any)
	assert.Equal(t, string(types.StatusValid), validation["status"])
	assert.Equal(t, 0.95, validation["confidence"])
	assert.Equal(t, "Key is active", validation["message"])
}

func TestToRisk_RoundTrip(t *testing.T) {
	match := &types.Match{
		RuleID:    "np.aws.1",
		RuleName:  "AWS API Key",
		FindingID: "abc123def456",
		Snippet: types.Snippet{
			Before:   []byte("key="),
			Matching: []byte("AKIAIOSFODNN7EXAMPLE"),
			After:    []byte("\n"),
		},
		Location: types.Location{
			Offset: types.OffsetSpan{Start: 4, End: 24},
			Source: types.SourceSpan{
				Start: types.SourcePoint{Line: 1, Column: 5},
				End:   types.SourcePoint{Line: 1, Column: 25},
			},
		},
	}

	result := secrets.SecretScanResult{
		ResourceRef:  "arn:aws:lambda:us-east-1:123456789012:function:demo",
		ResourceType: "AWS::Lambda::Function",
		Region:       "us-east-1",
		AccountID:    "123456789012",
		Platform:     "aws",
		Label:        "index.js",
		Match:        match,
	}

	risk, err := result.ToRisk()
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(risk.Context, &decoded))

	assert.Equal(t, "abc123def456", decoded["finding_id"])
	assert.Equal(t, "AWS API Key", decoded["rule_name"])
	assert.Equal(t, "np.aws.1", decoded["rule_text_id"])
	assert.Equal(t, "arn:aws:lambda:us-east-1:123456789012:function:demo", decoded["resource_ref"])
}

func TestRiskFromScanResult_ImpactedResourceID_IncludesFindingID(t *testing.T) {
	match := &types.Match{
		RuleID:    "np.aws.1",
		RuleName:  "AWS API Key",
		FindingID: "abc123def456",
	}

	result := secrets.SecretScanResult{
		ResourceRef: "arn:aws:lambda:us-east-1:123:function:demo",
		Platform:    "aws",
		Label:       "main.py",
		Match:       match,
	}

	out := pipeline.New[model.AurelianModel]()
	go func() {
		defer out.Close()
		require.NoError(t, secrets.RiskFromScanResult(result, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)

	risk := items[0].(output.AurelianRisk)
	assert.Equal(t, "arn:aws:lambda:us-east-1:123:function:demo:abc123de", risk.ImpactedResourceID)
	assert.Equal(t, "abc123def456", risk.DeduplicationID)
	assert.Equal(t, "aws-secret-aws", risk.Name)
	assert.Equal(t, output.RiskSeverityMedium, risk.Severity)
}

func TestRiskFromScanResult_ImpactedResourceID_NoFindingID(t *testing.T) {
	match := &types.Match{
		RuleID:   "np.aws.1",
		RuleName: "AWS API Key",
	}

	result := secrets.SecretScanResult{
		ResourceRef: "i-08da3f571f1346176",
		Platform:    "aws",
		Label:       "user-data",
		Match:       match,
	}

	out := pipeline.New[model.AurelianModel]()
	go func() {
		defer out.Close()
		require.NoError(t, secrets.RiskFromScanResult(result, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)

	risk := items[0].(output.AurelianRisk)
	assert.Equal(t, "i-08da3f571f1346176", risk.ImpactedResourceID, "should use bare ResourceRef when FindingID is empty")
}
