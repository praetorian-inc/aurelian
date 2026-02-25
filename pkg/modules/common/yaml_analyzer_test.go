package common_test

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/modules/common"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestYAMLAnalyzerMatchesRule(t *testing.T) {
	rule := common.YAMLRule{
		ID:           "test-lambda-no-auth",
		Name:         "Lambda Function URL Without Authentication",
		ResourceType: "AWS::Lambda::Function",
		Severity:     "high",
		Description:  "Test rule",
		Match: []common.MatchCondition{
			{Field: "FunctionUrl", Exists: boolPtr(true)},
			{Field: "FunctionUrlAuthType", Equals: "NONE"},
		},
	}

	analyzer := common.NewYAMLAnalyzer([]common.YAMLRule{rule})

	vulnerable := output.AWSResource{
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

	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, analyzer.Run, p2)

	results, err := p2.Collect()
	require.NoError(t, err)
	require.Len(t, results, 1)

	finding, ok := results[0].(plugin.Finding)
	require.True(t, ok)

	assert.Equal(t, "test-lambda-no-auth", finding.RuleID)
	assert.Equal(t, "high", finding.Severity)
	assert.Equal(t, "vulnerable-function", finding.Resource.ResourceID)
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

	secure := output.AWSResource{
		ResourceType: "AWS::Lambda::Function",
		Properties: map[string]any{
			"FunctionUrl":         "https://abc123.lambda-url.us-east-1.on.aws/",
			"FunctionUrlAuthType": "AWS_IAM",
		},
	}

	cfg := plugin.Config{
		Context: context.Background(),
		Args:    map[string]any{"resource": secure},
	}

	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, analyzer.Run, p2)

	results, err := p2.Collect()
	require.NoError(t, err)
	assert.Empty(t, results, "Secure resource should produce no findings")
}

func boolPtr(b bool) *bool {
	return &b
}
