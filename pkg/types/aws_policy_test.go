package types

import (
	"reflect"
	"testing"
)

func TestNewPolicy(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		expectError bool
		policy      *Policy
	}{
		{
			name: "Valid policy",
			input: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::example-bucket/*"
					}
				]
			}`,
			expectError: false,
			policy: &Policy{
				Version: "2012-10-17",
				Statement: &PolicyStatementList{
					{
						Effect:   "Allow",
						Action:   NewDynaString([]string{"s3:GetObject"}),
						Resource: NewDynaString([]string{"arn:aws:s3:::example-bucket/*"}),
					},
				},
			},
		},
		{
			name: "Valid StringList",
			input: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": ["s3:GetObject", "s3:ListBucket"],
						"Resource": "arn:aws:s3:::example-bucket/*"
					}
				]
			}`,
			expectError: false,
			policy: &Policy{
				Version: "2012-10-17",
				Statement: &PolicyStatementList{
					{
						Effect:   "Allow",
						Action:   NewDynaString([]string{"s3:GetObject", "s3:ListBucket"}),
						Resource: NewDynaString([]string{"arn:aws:s3:::example-bucket/*"}),
					},
				},
			},
		},
		{
			name: "Missing version",
			input: `{
				"Statement": [
					{
						"Effect": "Allow",
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::example-bucket/*"
					}
				]
			}`,
			expectError: true,
		},
		{
			name: "Empty statements",
			input: `{
				"Version": "2012-10-17",
				"Statement": []
			}`,
			expectError: true,
		},
		{
			name: "Invalid JSON",
			input: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::example-bucket/*"
					}
				`,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := NewPolicyFromJSON([]byte(tc.input))
			if (err != nil) != tc.expectError {
				t.Errorf("Expected error: %v, got: %v", tc.expectError, err)
			} else if tc.policy != nil && policy != nil {
				// deep compare policy
				if !reflect.DeepEqual(policy, tc.policy) {
					t.Errorf("Expected policy: %v, got: %v", tc.policy, policy)
				}
			}
		})
	}
}
