package iam

import "testing"

// TestPrivescGapActionsAllowlisted asserts the privesc actions added to close the
// Phase-3 known-gap skips are recognized as priv-esc actions. Each case fails if
// the corresponding allowlist entry in action.go is removed.
func TestPrivescGapActionsAllowlisted(t *testing.T) {
	actions := []string{
		"iam:DeleteAccessKey",
		"ssm:CreateAssociation",
		"datapipeline:CreatePipeline",
		"datapipeline:PutPipelineDefinition",
		"datapipeline:ActivatePipeline",
		"cloudformation:CreateStackInstances",
		"bedrock-agentcore:StartCodeInterpreterSession",
		"bedrock-agentcore:InvokeCodeInterpreter",
	}
	for _, action := range actions {
		t.Run(action, func(t *testing.T) {
			if !IsPrivEscAction(action) {
				t.Errorf("%s should be recognized as a privilege escalation action", action)
			}
		})
	}
}

// TestPrivescGapActionResourceMappings asserts the action→resource map entries added
// to close the Phase-3 known-gap skips resolve against the expected resource ARNs.
// Each case fails if the corresponding ActionResourceMap entry is removed.
func TestPrivescGapActionResourceMappings(t *testing.T) {
	testCases := []struct {
		name     string
		action   string
		resource string
		expected bool
	}{
		{
			name:     "iam:DeleteAccessKey on user ARN",
			action:   "iam:DeleteAccessKey",
			resource: "arn:aws:iam::123456789012:user/victim",
			expected: true,
		},
		{
			name:     "iam:DeleteAccessKey on role ARN (wrong resource type)",
			action:   "iam:DeleteAccessKey",
			resource: "arn:aws:iam::123456789012:role/victim",
			expected: false,
		},
		{
			name:     "ssm:CreateAssociation on EC2 instance ARN",
			action:   "ssm:CreateAssociation",
			resource: "arn:aws:ec2:us-east-2:123456789012:instance/i-0e2d24b9aec1606c2",
			expected: true,
		},
		{
			name:     "ssm:CreateAssociation on SSM service stub",
			action:   "ssm:CreateAssociation",
			resource: "arn:aws:ssm:*:*:*",
			expected: true,
		},
		{
			name:     "ssm:CreateAssociation on S3 bucket (wrong resource type)",
			action:   "ssm:CreateAssociation",
			resource: "arn:aws:s3:::my-bucket",
			expected: false,
		},
		{
			name:     "cloudformation:CreateStackInstances on stackset ARN",
			action:   "cloudformation:CreateStackInstances",
			resource: "arn:aws:cloudformation:us-east-2:123456789012:stackset/admin-set:id",
			expected: true,
		},
		{
			name:     "cloudformation:CreateStackInstances on CFN service stub",
			action:   "cloudformation:CreateStackInstances",
			resource: "arn:aws:cloudformation:*:*:*",
			expected: true,
		},
		{
			name:     "datapipeline:CreatePipeline on pipeline ARN",
			action:   "datapipeline:CreatePipeline",
			resource: "arn:aws:datapipeline:us-east-2:123456789012:pipeline/df-0123456789",
			expected: true,
		},
		{
			name:     "datapipeline:PutPipelineDefinition on DataPipeline service stub",
			action:   "datapipeline:PutPipelineDefinition",
			resource: "arn:aws:datapipeline:*:*:*",
			expected: true,
		},
		{
			name:     "datapipeline:ActivatePipeline on IAM role (wrong resource type)",
			action:   "datapipeline:ActivatePipeline",
			resource: "arn:aws:iam::123456789012:role/admin",
			expected: false,
		},
		{
			name:     "bedrock-agentcore:StartCodeInterpreterSession on service stub",
			action:   "bedrock-agentcore:StartCodeInterpreterSession",
			resource: "arn:aws:bedrock-agentcore:*:*:*",
			expected: true,
		},
		{
			name:     "bedrock-agentcore:InvokeCodeInterpreter on service stub",
			action:   "bedrock-agentcore:InvokeCodeInterpreter",
			resource: "arn:aws:bedrock-agentcore:*:*:*",
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IsValidActionForResource(tc.action, tc.resource)
			if result != tc.expected {
				t.Errorf("expected %v, got %v for action %s and resource %s",
					tc.expected, result, tc.action, tc.resource)
			}
		})
	}
}
