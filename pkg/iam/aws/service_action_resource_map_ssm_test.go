package aws

import (
	"testing"
)

func TestSSMSendCommandMapping(t *testing.T) {
	testCases := []struct {
		name     string
		action   string
		resource string
		expected bool
	}{
		{
			name:     "ssm:SendCommand with EC2 instance",
			action:   "ssm:SendCommand",
			resource: "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
			expected: true,
		},
		{
			name:     "ssm:SendCommand with non-EC2 resource",
			action:   "ssm:SendCommand",
			resource: "arn:aws:iam::123456789012:role/test-role",
			expected: false,
		},
		{
			name:     "ssm:SendCommand with S3 bucket",
			action:   "ssm:SendCommand",
			resource: "arn:aws:s3:::my-bucket/*",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IsValidActionForResource(tc.action, tc.resource)
			if result != tc.expected {
				t.Errorf("Expected %v, but got %v for action %s and resource %s",
					tc.expected, result, tc.action, tc.resource)
			}
		})
	}
}

func TestSSMSendCommandPrivilegeEscalation(t *testing.T) {
	// Test that ssm:SendCommand is in the privilege escalation list
	if !isPrivEscAction("ssm:SendCommand") {
		t.Error("ssm:SendCommand should be recognized as a privilege escalation action")
	}
}

func TestSSMSendCommandResourcePatterns(t *testing.T) {
	// Test that ssm:SendCommand returns EC2 instance patterns
	action := Action("ssm:SendCommand")
	patterns := getResourcePatternsFromAction(action)

	if len(patterns) == 0 {
		t.Fatal("ssm:SendCommand should return at least one resource pattern")
	}

	// Test that the pattern matches EC2 instances
	ec2InstanceArn := "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"
	matched := false
	for _, pattern := range patterns {
		if pattern.MatchString(ec2InstanceArn) {
			matched = true
			break
		}
	}

	if !matched {
		t.Errorf("ssm:SendCommand patterns should match EC2 instance ARN: %s", ec2InstanceArn)
	}
}