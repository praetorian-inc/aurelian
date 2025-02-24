package aws

import (
	"reflect"
	"testing"

	"github.com/praetorian-inc/nebula/pkg/types"
)

func TestEvaluateStatement(t *testing.T) {
	tests := []struct {
		name              string
		stmt              *types.PolicyStatement
		requestedAction   string
		requestedResource string
		context           *RequestContext
		expected          *StatementEvaluation
	}{
		{
			name: "Basic allow action match",
			stmt: &types.PolicyStatement{
				Effect:   "Allow",
				Action:   &types.DynaString{"s3:GetObject"},
				Resource: &types.DynaString{"arn:aws:s3:::mybucket/*"},
			},
			requestedAction:   "s3:GetObject",
			requestedResource: "arn:aws:s3:::mybucket/myfile.txt",
			context:           &RequestContext{},
			expected: &StatementEvaluation{
				ExplicitAllow:   true,
				ExplicitDeny:    false,
				ImplicitDeny:    false,
				MatchedAction:   true,
				MatchedResource: true,
			},
		},
		{
			name: "Basic deny action match",
			stmt: &types.PolicyStatement{
				Effect:   "Deny",
				Action:   &types.DynaString{"s3:DeleteBucket"},
				Resource: &types.DynaString{"*"},
			},
			requestedAction:   "s3:DeleteBucket",
			requestedResource: "arn:aws:s3:::mybucket",
			context:           &RequestContext{},
			expected: &StatementEvaluation{
				ExplicitAllow:   false,
				ExplicitDeny:    true,
				ImplicitDeny:    false,
				MatchedAction:   true,
				MatchedResource: true,
			},
		},
		{
			name: "Action does not match",
			stmt: &types.PolicyStatement{
				Effect:   "Allow",
				Action:   &types.DynaString{"s3:GetObject"},
				Resource: &types.DynaString{"*"},
			},
			requestedAction:   "s3:PutObject",
			requestedResource: "arn:aws:s3:::mybucket/myfile.txt",
			context:           &RequestContext{},
			expected: &StatementEvaluation{
				ExplicitAllow:   false,
				ExplicitDeny:    false,
				ImplicitDeny:    true,
				MatchedAction:   false,
				MatchedResource: false,
			},
		},
		{
			name: "Resource does not match",
			stmt: &types.PolicyStatement{
				Effect:   "Allow",
				Action:   &types.DynaString{"s3:GetObject"},
				Resource: &types.DynaString{"arn:aws:s3:::otherbucket/*"},
			},
			requestedAction:   "s3:GetObject",
			requestedResource: "arn:aws:s3:::mybucket/myfile.txt",
			context:           &RequestContext{},
			expected: &StatementEvaluation{
				ExplicitAllow:   false,
				ExplicitDeny:    false,
				ImplicitDeny:    true,
				MatchedAction:   true,
				MatchedResource: false,
			},
		},
		{
			name: "NotAction match",
			stmt: &types.PolicyStatement{
				Effect:    "Allow",
				NotAction: &types.DynaString{"s3:DeleteBucket", "s3:DeleteObject"},
				Resource:  &types.DynaString{"*"},
			},
			requestedAction:   "s3:GetObject",
			requestedResource: "arn:aws:s3:::mybucket/myfile.txt",
			context:           &RequestContext{},
			expected: &StatementEvaluation{
				ExplicitAllow:   true,
				ExplicitDeny:    false,
				ImplicitDeny:    false,
				MatchedAction:   true,
				MatchedResource: true,
			},
		},
		{
			name: "NotResource match",
			stmt: &types.PolicyStatement{
				Effect:      "Allow",
				Action:      &types.DynaString{"s3:GetObject"},
				NotResource: &types.DynaString{"arn:aws:s3:::secretbucket/*"},
			},
			requestedAction:   "s3:GetObject",
			requestedResource: "arn:aws:s3:::mybucket/myfile.txt",
			context:           &RequestContext{},
			expected: &StatementEvaluation{
				ExplicitAllow:   true,
				ExplicitDeny:    false,
				ImplicitDeny:    false,
				MatchedAction:   true,
				MatchedResource: true,
			},
		},
		{
			name: "Condition match",
			stmt: &types.PolicyStatement{
				Effect:   "Allow",
				Action:   &types.DynaString{"s3:GetObject"},
				Resource: &types.DynaString{"*"},
				Condition: &types.Condition{
					"StringEquals": {
						"aws:username": []string{"test-user"},
					},
				},
			},
			requestedAction:   "s3:GetObject",
			requestedResource: "arn:aws:s3:::mybucket/myfile.txt",
			context: &RequestContext{
				RequestParameters: map[string]string{
					"aws:username": "test-user",
				},
			},
			expected: &StatementEvaluation{
				ExplicitAllow:   true,
				ExplicitDeny:    false,
				ImplicitDeny:    false,
				MatchedAction:   true,
				MatchedResource: true,
			},
		},
		{
			name: "Condition does not match",
			stmt: &types.PolicyStatement{
				Effect:   "Allow",
				Action:   &types.DynaString{"s3:GetObject"},
				Resource: &types.DynaString{"*"},
				Condition: &types.Condition{
					"StringEquals": {
						"aws:username": []string{"test-user"},
					},
				},
			},
			requestedAction:   "s3:GetObject",
			requestedResource: "arn:aws:s3:::mybucket/myfile.txt",
			context: &RequestContext{
				RequestParameters: map[string]string{
					"aws:username": "wrong-user",
				},
			},
			expected: &StatementEvaluation{
				ExplicitAllow:   false,
				ExplicitDeny:    false,
				ImplicitDeny:    true,
				MatchedAction:   true,
				MatchedResource: true,
			},
		},
		{
			name: "No action specified",
			stmt: &types.PolicyStatement{
				Effect:   "Allow",
				Resource: &types.DynaString{"*"},
			},
			requestedAction:   "s3:GetObject",
			requestedResource: "arn:aws:s3:::mybucket/myfile.txt",
			context:           &RequestContext{},
			expected: &StatementEvaluation{
				ExplicitAllow:   false,
				ExplicitDeny:    false,
				ImplicitDeny:    true,
				MatchedAction:   false,
				MatchedResource: false,
			},
		},
		{
			name: "No resource specified",
			stmt: &types.PolicyStatement{
				Effect: "Allow",
				Action: &types.DynaString{"s3:GetObject"},
			},
			requestedAction:   "s3:GetObject",
			requestedResource: "arn:aws:s3:::mybucket/myfile.txt",
			context:           &RequestContext{},
			expected: &StatementEvaluation{
				ExplicitAllow:   false,
				ExplicitDeny:    false,
				ImplicitDeny:    true,
				MatchedAction:   true,
				MatchedResource: false,
			},
		},
		{
			name: "Wildcard action match",
			stmt: &types.PolicyStatement{
				Effect:   "Allow",
				Action:   &types.DynaString{"s3:*"},
				Resource: &types.DynaString{"*"},
			},
			requestedAction:   "s3:GetObject",
			requestedResource: "arn:aws:s3:::mybucket/myfile.txt",
			context:           &RequestContext{},
			expected: &StatementEvaluation{
				ExplicitAllow:   true,
				ExplicitDeny:    false,
				ImplicitDeny:    false,
				MatchedAction:   true,
				MatchedResource: true,
			},
		},
		{
			name: "Multiple actions with one match",
			stmt: &types.PolicyStatement{
				Effect:   "Allow",
				Action:   &types.DynaString{"s3:PutObject", "s3:GetObject", "s3:DeleteObject"},
				Resource: &types.DynaString{"*"},
			},
			requestedAction:   "s3:GetObject",
			requestedResource: "arn:aws:s3:::mybucket/myfile.txt",
			context:           &RequestContext{},
			expected: &StatementEvaluation{
				ExplicitAllow:   true,
				ExplicitDeny:    false,
				ImplicitDeny:    false,
				MatchedAction:   true,
				MatchedResource: true,
			},
		},
		{
			name: "Principal match",
			stmt: &types.PolicyStatement{
				Effect:   "Allow",
				Action:   &types.DynaString{"sts:AssumeRole"},
				Resource: &types.DynaString{"arn:aws:iam::123456789012:role/test-role"},
				Principal: &types.Principal{
					AWS: &types.DynaString{"arn:aws:iam::123456789012:root"},
				},
			},
			requestedAction:   "sts:AssumeRole",
			requestedResource: "arn:aws:iam::123456789012:role/test-role",
			context: &RequestContext{
				PrincipalArn: "arn:aws:iam::123456789012:role/test-role",
			},
			expected: &StatementEvaluation{
				ExplicitAllow:    true,
				ExplicitDeny:     false,
				ImplicitDeny:     false,
				MatchedAction:    true,
				MatchedResource:  true,
				MatchedPrincipal: true,
			},
		},
		{
			name: "Principal match service",
			stmt: &types.PolicyStatement{
				Effect:   "Allow",
				Action:   &types.DynaString{"sts:AssumeRole"},
				Resource: &types.DynaString{"arn:aws:iam::123456789012:role/test-role"},
				Principal: &types.Principal{
					Service: &types.DynaString{"glue.amazonaws.com"},
				},
			},
			requestedAction:   "sts:AssumeRole",
			requestedResource: "arn:aws:iam::123456789012:role/test-role",
			context: &RequestContext{
				PrincipalArn: "glue.amazonaws.com",
			},
			expected: &StatementEvaluation{
				ExplicitAllow:    true,
				ExplicitDeny:     false,
				ImplicitDeny:     false,
				MatchedAction:    true,
				MatchedResource:  true,
				MatchedPrincipal: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluateStatement(tt.stmt, tt.requestedAction, tt.requestedResource, tt.context)
			t.Logf("EvaluateStatement: ExplicitAllow: %v, ExplicitDeny: %v, ImplicitDeny: %v, MatchedAction: %v, MatchedResource: %v, MatchedPrincipal: %v", got.ExplicitAllow, got.ExplicitDeny, got.ImplicitDeny, got.MatchedAction, got.MatchedResource, got.MatchedPrincipal)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("evaluateStatement() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestMatchesPattern(t *testing.T) {
	testCases := []struct {
		pattern string
		input   string
		matched bool
	}{
		// Test case 1: Exact match
		{
			pattern: "example.com",
			input:   "example.com",
			matched: true,
		},
		// Test case 2: Wildcard match
		{
			pattern: "*.example.com",
			input:   "sub.example.com",
			matched: true,
		},
		// Test case 3: Single character match
		{
			pattern: "exa?ple.com",
			input:   "example.com",
			matched: true,
		},
		// Test case 4: No match
		{
			pattern: "example.com",
			input:   "test.com",
			matched: false,
		},
		// Test case 5: Wildcard no match
		{
			pattern: "*.example.com",
			input:   "example.org",
			matched: false,
		},
		// Test case 6: Single character no match
		{
			pattern: "exa?ple.com",
			input:   "exaple.com",
			matched: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.pattern+"_"+tc.input, func(t *testing.T) {
			result := matchesPattern(tc.pattern, tc.input)
			if result != tc.matched {
				t.Errorf("Expected %v, but got %v for pattern %s and input %s", tc.matched, result, tc.pattern, tc.input)
			}
		})
	}
}

func TestMatchesActions(t *testing.T) {
	testCases := []struct {
		actions         *types.DynaString
		requestedAction string
		matched         bool
	}{
		// Test case 1: Exact match
		{
			actions:         &types.DynaString{"s3:GetObject"},
			requestedAction: "s3:GetObject",
			matched:         true,
		},
		// Test case 2: Wildcard match
		{
			actions:         &types.DynaString{"s3:*"},
			requestedAction: "s3:ListBucket",
			matched:         true,
		},
		// Test case 3: No match
		{
			actions:         &types.DynaString{"s3:GetObject"},
			requestedAction: "s3:PutObject",
			matched:         false,
		},
		// Test case 4: Multiple actions with match
		{
			actions:         &types.DynaString{"s3:GetObject", "s3:PutObject"},
			requestedAction: "s3:PutObject",
			matched:         true,
		},
		// Test case 5: Multiple actions without match
		{
			actions:         &types.DynaString{"s3:GetObject", "s3:ListBucket"},
			requestedAction: "s3:DeleteObject",
			matched:         false,
		},
		// Test case 6: Wildcard no match
		{
			actions:         &types.DynaString{"ec2:*"},
			requestedAction: "s3:ListBucket",
			matched:         false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.requestedAction, func(t *testing.T) {
			result := matchesActions(tc.actions, tc.requestedAction)
			if result != tc.matched {
				t.Errorf("Expected %v, but got %v for actions %v and requestedAction %s", tc.matched, result, *tc.actions, tc.requestedAction)
			}
		})
	}
}
func TestMatchesResources(t *testing.T) {
	testCases := []struct {
		name              string
		resources         *types.DynaString
		requestedResource string
		matched           bool
		error             bool
	}{
		{
			name:              "Exact match",
			resources:         &types.DynaString{"arn:aws:s3:::example-bucket"},
			requestedResource: "arn:aws:s3:::example-bucket",
			matched:           true,
		},
		{
			name:              "Wildcard match",
			resources:         &types.DynaString{"arn:aws:s3:::example-*"},
			requestedResource: "arn:aws:s3:::example-bucket",
			matched:           true,
		},
		{
			name:              "No match",
			resources:         &types.DynaString{"arn:aws:s3:::example-bucket"},
			requestedResource: "arn:aws:s3:::another-bucket",
			matched:           false,
		},
		{
			name:              "Multiple resources with match",
			resources:         &types.DynaString{"arn:aws:s3:::example-bucket", "arn:aws:s3:::another-bucket"},
			requestedResource: "arn:aws:s3:::another-bucket",
			matched:           true,
		},
		{
			name:              "Multiple resources without match",
			resources:         &types.DynaString{"arn:aws:s3:::example-bucket", "arn:aws:s3:::another-bucket"},
			requestedResource: "arn:aws:s3:::different-bucket",
			matched:           false,
		},
		{
			name:              "Wildcard no match",
			resources:         &types.DynaString{"arn:aws:s3:::example-*"},
			requestedResource: "arn:aws:s3:::different-bucket",
			matched:           false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.requestedResource, func(t *testing.T) {
			result := MatchesResources(tc.resources, tc.requestedResource)
			if result != tc.matched {
				t.Errorf("Expected %v, but got %v for resources %v and requestedResource %s", tc.matched, result, *tc.resources, tc.requestedResource)
			}
		})
	}
}
