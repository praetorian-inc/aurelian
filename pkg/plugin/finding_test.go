package plugin_test

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

func TestFindingCreation(t *testing.T) {
	resource := &output.CloudResource{
		Platform:     "aws",
		ResourceType: "AWS::Lambda::Function",
		ResourceID:   "my-function",
		ARN:          "arn:aws:lambda:us-east-1:123456789012:function:my-function",
		Region:       "us-east-1",
		AccountRef:   "123456789012",
	}

	finding := plugin.Finding{
		RuleID:      "lambda-no-auth-function-url",
		Severity:    "high",
		Name:        "Lambda Function URL Without Authentication",
		Description: "Lambda function URL is publicly accessible without IAM authentication.",
		Resource:    *resource,
	}

	assert.Equal(t, "lambda-no-auth-function-url", finding.RuleID)
	assert.Equal(t, "high", finding.Severity)
	assert.Equal(t, "my-function", finding.Resource.ResourceID)
}
