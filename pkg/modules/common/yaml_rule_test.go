package common_test

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/modules/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestYAMLRuleParsing(t *testing.T) {
	ruleYAML := `
id: lambda-no-auth-function-url
name: Lambda Function URL Without Authentication
platform: aws
resource_type: AWS::Lambda::Function
severity: high
description: Lambda function URL is publicly accessible without IAM authentication.
references:
  - https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html
match:
  - field: FunctionUrl
    exists: true
  - field: FunctionUrlAuthType
    equals: NONE
`

	var rule common.YAMLRule
	err := yaml.Unmarshal([]byte(ruleYAML), &rule)
	require.NoError(t, err)

	assert.Equal(t, "lambda-no-auth-function-url", rule.ID)
	assert.Equal(t, "Lambda Function URL Without Authentication", rule.Name)
	assert.Equal(t, "aws", rule.Platform)
	assert.Equal(t, "AWS::Lambda::Function", rule.ResourceType)
	assert.Equal(t, "high", rule.Severity)
	assert.Len(t, rule.Match, 2)
	assert.Equal(t, "FunctionUrl", rule.Match[0].Field)
	assert.True(t, rule.Match[0].Exists != nil && *rule.Match[0].Exists)
	assert.Equal(t, "FunctionUrlAuthType", rule.Match[1].Field)
	assert.Equal(t, "NONE", rule.Match[1].Equals)
}
