package common_test

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/modules/common"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestYAMLAnalyzerMatchesRule(t *testing.T) {
	// Create analyzer with inline rule for testing
	rule := common.YAMLRule{
		ID:           "test-lambda-no-auth",
		Name:         "Lambda Function URL Without Authentication",
		Platform:     "aws",
		ResourceType: "AWS::Lambda::Function",
		Severity:     "high",
		Description:  "Test rule",
		Match: []common.MatchCondition{
			{Field: "FunctionUrl", Exists: boolPtr(true)},
			{Field: "FunctionUrlAuthType", Equals: "NONE"},
		},
	}

	analyzer := common.NewYAMLAnalyzer([]common.YAMLRule{rule})

	// Test resource that SHOULD match
	vulnerable := output.CloudResource{
		Platform:     "aws",
		ResourceType: "AWS::Lambda::Function",
		ResourceID:   "vulnerable-function",
		Properties: map[string]any{
			"FunctionUrl":         "https://abc123.lambda-url.us-east-1.on.aws/",
			"FunctionUrlAuthType": "NONE",
		},
	}

	cfg := plugin.Config{
		Context: context.Background(),
		Args:    map[string]any{"resource": vulnerable},
	}

	results, err := analyzer.Run(cfg)
	require.NoError(t, err)
	require.Len(t, results, 1)

	findings, ok := results[0].Data.([]plugin.Finding)
	require.True(t, ok)
	require.Len(t, findings, 1)

	assert.Equal(t, "test-lambda-no-auth", findings[0].RuleID)
	assert.Equal(t, "high", findings[0].Severity)
	assert.Equal(t, "vulnerable-function", findings[0].Resource.ResourceID)
}

func TestYAMLAnalyzerNoMatch(t *testing.T) {
	rule := common.YAMLRule{
		ID:           "test-lambda-no-auth",
		ResourceType: "AWS::Lambda::Function",
		Match: []common.MatchCondition{
			{Field: "FunctionUrl", Exists: boolPtr(true)},
			{Field: "FunctionUrlAuthType", Equals: "NONE"},
		},
	}

	analyzer := common.NewYAMLAnalyzer([]common.YAMLRule{rule})

	// Secure resource - should NOT match
	secure := output.CloudResource{
		ResourceType: "AWS::Lambda::Function",
		Properties: map[string]any{
			"FunctionUrl":         "https://abc123.lambda-url.us-east-1.on.aws/",
			"FunctionUrlAuthType": "AWS_IAM", // <- Authenticated
		},
	}

	cfg := plugin.Config{
		Context: context.Background(),
		Args:    map[string]any{"resource": secure},
	}

	results, err := analyzer.Run(cfg)
	require.NoError(t, err)
	require.Len(t, results, 1)

	findings, ok := results[0].Data.([]plugin.Finding)
	require.True(t, ok)
	assert.Empty(t, findings, "Secure resource should produce no findings")
}

func boolPtr(b bool) *bool {
	return &b
}
