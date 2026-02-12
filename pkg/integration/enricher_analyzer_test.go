package integration_test

import (
	"context"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/praetorian-inc/aurelian/pkg/modules/common"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestEnricherAnalyzerFlow(t *testing.T) {
	// Step 1: Start with raw resource (as CloudControl would return)
	resource := output.CloudResource{
		Platform:     "aws",
		ResourceType: "AWS::Lambda::Function",
		ResourceID:   "my-function",
		ARN:          "arn:aws:lambda:us-east-1:123456789012:function:my-function",
		Region:       "us-east-1",
		AccountRef:   "123456789012",
		Properties:   make(map[string]any),
	}

	// Step 2: Apply enrichers (simulating enumerator behavior)
	cfg := plugin.EnricherConfig{
		Context:   context.Background(),
		AWSConfig: aws.Config{},
	}

	// Mock enricher for testing
	mockEnricher := func(cfg plugin.EnricherConfig, r *output.CloudResource) error {
		r.Properties["FunctionUrl"] = "https://abc123.lambda-url.us-east-1.on.aws/"
		r.Properties["FunctionUrlAuthType"] = "NONE"
		return nil
	}

	err := mockEnricher(cfg, &resource)
	require.NoError(t, err)

	// Verify enrichment happened
	assert.Equal(t, "https://abc123.lambda-url.us-east-1.on.aws/", resource.Properties["FunctionUrl"])
	assert.Equal(t, "NONE", resource.Properties["FunctionUrlAuthType"])

	// Step 3: Load YAML rule
	ruleBytes, err := os.ReadFile("../modules/aws/rules/lambda/no-auth-function-url.yaml")
	require.NoError(t, err)

	var rule common.YAMLRule
	err = yaml.Unmarshal(ruleBytes, &rule)
	require.NoError(t, err)

	// Step 4: Run analyzer
	analyzer := common.NewYAMLAnalyzer([]common.YAMLRule{rule})
	analysisConfig := plugin.Config{
		Context: context.Background(),
		Args:    map[string]any{"resource": resource},
	}

	results, err := analyzer.Run(analysisConfig)
	require.NoError(t, err)
	require.Len(t, results, 1)

	findings, ok := results[0].Data.([]plugin.Finding)
	require.True(t, ok)
	require.Len(t, findings, 1)

	// Step 5: Verify finding
	finding := findings[0]
	assert.Equal(t, "lambda-no-auth-function-url", finding.RuleID)
	assert.Equal(t, "high", finding.Severity)
	assert.Equal(t, "Lambda Function URL Without Authentication", finding.Name)
	assert.Equal(t, "my-function", finding.Resource.ResourceID)
}

func TestEnricherAnalyzerFlowNoFinding(t *testing.T) {
	// Secure resource (authenticated function URL)
	resource := output.CloudResource{
		ResourceType: "AWS::Lambda::Function",
		ResourceID:   "secure-function",
		Properties: map[string]any{
			"FunctionUrl":         "https://xyz789.lambda-url.us-east-1.on.aws/",
			"FunctionUrlAuthType": "AWS_IAM", // <- Authenticated
		},
	}

	// Load rule
	ruleBytes, err := os.ReadFile("../modules/aws/rules/lambda/no-auth-function-url.yaml")
	require.NoError(t, err)

	var rule common.YAMLRule
	err = yaml.Unmarshal(ruleBytes, &rule)
	require.NoError(t, err)

	// Run analyzer
	analyzer := common.NewYAMLAnalyzer([]common.YAMLRule{rule})
	results, err := analyzer.Run(plugin.Config{
		Context: context.Background(),
		Args:    map[string]any{"resource": resource},
	})

	require.NoError(t, err)
	findings, _ := results[0].Data.([]plugin.Finding)
	assert.Empty(t, findings, "Secure resource should produce no findings")
}
