package iam

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
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
				PrincipalUsername: "test-user",
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
				PrincipalUsername: "wrong-user",
			},
			expected: &StatementEvaluation{
				ExplicitAllow:   false,
				ExplicitDeny:    false,
				ImplicitDeny:    true,
				MatchedAction:   true,
				MatchedResource: true,
				ConditionEvaluation: &ConditionEval{
					Result: ConditionFailed,
					KeyResults: map[string]KeyEvaluation{
						"aws:username": {
							Key:      "aws:username",
							Operator: "StringEquals",
							Values:   []string{"test-user"},
							Result:   ConditionFailed,
							Context:  "wrong-user",
						},
					},
				},
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
		{
			name: "Principal match service missing source arn",
			stmt: &types.PolicyStatement{
				Effect:   "Allow",
				Action:   &types.DynaString{"sts:AssumeRole"},
				Resource: &types.DynaString{"arn:aws:iam::123456789012:role/test-role"},
				Principal: &types.Principal{
					Service: &types.DynaString{"glue.amazonaws.com"},
				},
				Condition: &types.Condition{
					"StringEquals": {
						"aws:SourceAccount": types.DynaString{"123456789012"},
					},
					"ArnLike": {
						"aws:SourceArn": types.DynaString{"arn:aws:iam::123456789012:glue/*"},
					},
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
				ConditionEvaluation: &ConditionEval{
					Result: ConditionInconclusive,
				},
			},
		},
		{
			name: "GitHub Actions federated principal exact repository match",
			stmt: &types.PolicyStatement{
				Effect:   "Allow",
				Action:   &types.DynaString{"sts:AssumeRole"},
				Resource: &types.DynaString{"arn:aws:iam::123456789012:role/github-actions-role"},
				Principal: &types.Principal{
					Federated: &types.DynaString{"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
				},
				Condition: &types.Condition{
					"StringEquals": {
						"token.actions.githubusercontent.com:sub": types.DynaString{"repo:octocat/hello-world:ref:refs/heads/main"},
						"token.actions.githubusercontent.com:aud": types.DynaString{"sts.amazonaws.com"},
					},
				},
			},
			requestedAction:   "sts:AssumeRole",
			requestedResource: "arn:aws:iam::123456789012:role/github-actions-role",
			context: &RequestContext{
				PrincipalArn: "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
				RequestParameters: map[string]string{
					"token.actions.githubusercontent.com:sub": "repo:octocat/hello-world:ref:refs/heads/main",
					"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				},
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
			name: "GitHub Actions federated principal wildcard repository match",
			stmt: &types.PolicyStatement{
				Effect:   "Allow",
				Action:   &types.DynaString{"sts:AssumeRole"},
				Resource: &types.DynaString{"arn:aws:iam::123456789012:role/github-actions-role"},
				Principal: &types.Principal{
					Federated: &types.DynaString{"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
				},
				Condition: &types.Condition{
					"StringLike": {
						"token.actions.githubusercontent.com:sub": types.DynaString{"repo:octocat/hello-world:*"},
						"token.actions.githubusercontent.com:aud": types.DynaString{"sts.amazonaws.com"},
					},
				},
			},
			requestedAction:   "sts:AssumeRole",
			requestedResource: "arn:aws:iam::123456789012:role/github-actions-role",
			context: &RequestContext{
				PrincipalArn: "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
				RequestParameters: map[string]string{
					"token.actions.githubusercontent.com:sub": "repo:octocat/hello-world:environment:production",
					"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				},
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
			name: "GitHub Actions federated principal environment-specific match",
			stmt: &types.PolicyStatement{
				Effect:   "Allow",
				Action:   &types.DynaString{"sts:AssumeRole"},
				Resource: &types.DynaString{"arn:aws:iam::123456789012:role/prod-deploy-role"},
				Principal: &types.Principal{
					Federated: &types.DynaString{"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
				},
				Condition: &types.Condition{
					"StringEquals": {
						"token.actions.githubusercontent.com:sub": types.DynaString{"repo:company/app:environment:production"},
						"token.actions.githubusercontent.com:aud": types.DynaString{"sts.amazonaws.com"},
					},
				},
			},
			requestedAction:   "sts:AssumeRole",
			requestedResource: "arn:aws:iam::123456789012:role/prod-deploy-role",
			context: &RequestContext{
				PrincipalArn: "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
				RequestParameters: map[string]string{
					"token.actions.githubusercontent.com:sub": "repo:company/app:environment:production",
					"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				},
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
			name: "GitHub Actions federated principal wrong repository",
			stmt: &types.PolicyStatement{
				Effect:   "Allow",
				Action:   &types.DynaString{"sts:AssumeRole"},
				Resource: &types.DynaString{"arn:aws:iam::123456789012:role/github-actions-role"},
				Principal: &types.Principal{
					Federated: &types.DynaString{"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
				},
				Condition: &types.Condition{
					"StringEquals": {
						"token.actions.githubusercontent.com:sub": types.DynaString{"repo:octocat/hello-world:ref:refs/heads/main"},
						"token.actions.githubusercontent.com:aud": types.DynaString{"sts.amazonaws.com"},
					},
				},
			},
			requestedAction:   "sts:AssumeRole",
			requestedResource: "arn:aws:iam::123456789012:role/github-actions-role",
			context: &RequestContext{
				PrincipalArn: "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
				RequestParameters: map[string]string{
					"token.actions.githubusercontent.com:sub": "repo:different/repo:ref:refs/heads/main",
					"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				},
			},
			expected: &StatementEvaluation{
				ExplicitAllow:   false,
				ExplicitDeny:    false,
				ImplicitDeny:    true,
				MatchedAction:   true,
				MatchedResource: true,
				MatchedPrincipal: true,
				ConditionEvaluation: &ConditionEval{
					Result: ConditionFailed,
					KeyResults: map[string]KeyEvaluation{
						"token.actions.githubusercontent.com:sub": {
							Key:      "token.actions.githubusercontent.com:sub",
							Operator: "StringEquals",
							Values:   []string{"repo:octocat/hello-world:ref:refs/heads/main"},
							Result:   ConditionFailed,
							Context:  "repo:different/repo:ref:refs/heads/main",
						},
					},
				},
			},
		},
		{
			name: "GitHub Actions federated principal pull request access",
			stmt: &types.PolicyStatement{
				Effect:   "Allow",
				Action:   &types.DynaString{"sts:AssumeRole"},
				Resource: &types.DynaString{"arn:aws:iam::123456789012:role/pr-test-role"},
				Principal: &types.Principal{
					Federated: &types.DynaString{"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
				},
				Condition: &types.Condition{
					"StringLike": {
						"token.actions.githubusercontent.com:sub": types.DynaString{"repo:company/webapp:pull_request"},
						"token.actions.githubusercontent.com:aud": types.DynaString{"sts.amazonaws.com"},
					},
				},
			},
			requestedAction:   "sts:AssumeRole",
			requestedResource: "arn:aws:iam::123456789012:role/pr-test-role",
			context: &RequestContext{
				PrincipalArn: "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
				RequestParameters: map[string]string{
					"token.actions.githubusercontent.com:sub": "repo:company/webapp:pull_request",
					"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				},
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
			name: "GitHub Actions federated principal multi-repository wildcard",
			stmt: &types.PolicyStatement{
				Effect:   "Allow",
				Action:   &types.DynaString{"sts:AssumeRole"},
				Resource: &types.DynaString{"arn:aws:iam::123456789012:role/org-wide-role"},
				Principal: &types.Principal{
					Federated: &types.DynaString{"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
				},
				Condition: &types.Condition{
					"StringLike": {
						"token.actions.githubusercontent.com:sub": types.DynaString{"repo:myorg/*:ref:refs/heads/main"},
						"token.actions.githubusercontent.com:aud": types.DynaString{"sts.amazonaws.com"},
					},
				},
			},
			requestedAction:   "sts:AssumeRole",
			requestedResource: "arn:aws:iam::123456789012:role/org-wide-role",
			context: &RequestContext{
				PrincipalArn: "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
				RequestParameters: map[string]string{
					"token.actions.githubusercontent.com:sub": "repo:myorg/service-a:ref:refs/heads/main",
					"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				},
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
			name: "GitHub Actions federated principal missing audience",
			stmt: &types.PolicyStatement{
				Effect:   "Allow",
				Action:   &types.DynaString{"sts:AssumeRole"},
				Resource: &types.DynaString{"arn:aws:iam::123456789012:role/github-actions-role"},
				Principal: &types.Principal{
					Federated: &types.DynaString{"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
				},
				Condition: &types.Condition{
					"StringEquals": {
						"token.actions.githubusercontent.com:sub": types.DynaString{"repo:octocat/hello-world:ref:refs/heads/main"},
						"token.actions.githubusercontent.com:aud": types.DynaString{"sts.amazonaws.com"},
					},
				},
			},
			requestedAction:   "sts:AssumeRole",
			requestedResource: "arn:aws:iam::123456789012:role/github-actions-role",
			context: &RequestContext{
				PrincipalArn: "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
				RequestParameters: map[string]string{
					"token.actions.githubusercontent.com:sub": "repo:octocat/hello-world:ref:refs/heads/main",
					// Missing audience key
				},
			},
			expected: &StatementEvaluation{
				ExplicitAllow:   false,
				ExplicitDeny:    false,
				ImplicitDeny:    true,
				MatchedAction:   true,
				MatchedResource: true,
				MatchedPrincipal: true,
				ConditionEvaluation: &ConditionEval{
					Result: ConditionFailed,
					KeyResults: map[string]KeyEvaluation{
						"token.actions.githubusercontent.com:aud": {
							Key:      "token.actions.githubusercontent.com:aud",
							Operator: "StringEquals",
							Values:   []string{"sts.amazonaws.com"},
							Result:   ConditionFailed,
							Context:  "",
						},
					},
				},
			},
		},
		{
			name: "GitHub Actions deny statement blocks access",
			stmt: &types.PolicyStatement{
				Effect:   "Deny",
				Action:   &types.DynaString{"sts:AssumeRole"},
				Resource: &types.DynaString{"arn:aws:iam::123456789012:role/sensitive-role"},
				Principal: &types.Principal{
					Federated: &types.DynaString{"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
				},
				Condition: &types.Condition{
					"StringLike": {
						"token.actions.githubusercontent.com:sub": types.DynaString{"repo:untrusted/*"},
					},
				},
			},
			requestedAction:   "sts:AssumeRole",
			requestedResource: "arn:aws:iam::123456789012:role/sensitive-role",
			context: &RequestContext{
				PrincipalArn: "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
				RequestParameters: map[string]string{
					"token.actions.githubusercontent.com:sub": "repo:untrusted/malicious:ref:refs/heads/main",
					"token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
				},
			},
			expected: &StatementEvaluation{
				ExplicitAllow:    false,
				ExplicitDeny:     true,
				ImplicitDeny:     false,
				MatchedAction:    true,
				MatchedResource:  true,
				MatchedPrincipal: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NoError(t, tt.context.PopulateDefaultRequestConditionKeys(tt.requestedResource))
			got := evaluateStatement(tt.stmt, tt.requestedAction, tt.requestedResource, tt.context)
			t.Logf("EvaluateStatement: ExplicitAllow: %v, ExplicitDeny: %v, ImplicitDeny: %v, MatchedAction: %v, MatchedResource: %v, MatchedPrincipal: %v", got.ExplicitAllow, got.ExplicitDeny, got.ImplicitDeny, got.MatchedAction, got.MatchedResource, got.MatchedPrincipal)
			assert.Equal(t, got.ExplicitAllow, tt.expected.ExplicitAllow)
			assert.Equal(t, got.ExplicitDeny, tt.expected.ExplicitDeny)
			assert.Equal(t, got.ImplicitDeny, tt.expected.ImplicitDeny)
			assert.Equal(t, got.MatchedAction, tt.expected.MatchedAction)
			assert.Equal(t, got.MatchedResource, tt.expected.MatchedResource)
			assert.Equal(t, got.MatchedPrincipal, tt.expected.MatchedPrincipal)
			if tt.expected.ConditionEvaluation != nil {
				assert.Equal(t, got.ConditionEvaluation.Result, tt.expected.ConditionEvaluation.Result)
			}

			// if !reflect.DeepEqual(got, tt.expected) {
			// 	t.Errorf("evaluateStatement() = %v, want %v", got, tt.expected)
			// }
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
			result := MatchesPattern(tc.pattern, tc.input)
			if result != tc.matched {
				t.Errorf("Expected %v, but got %v for pattern %s and input %s", tc.matched, result, tc.pattern, tc.input)
			}
		})
	}
}

func TestMatchesPattern_RegexMetacharacterEscaping(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		input   string
		want    bool
	}{
		// Parentheses
		{
			name:    "parentheses match literal",
			pattern: "arn:aws:iam::*:role/my-role(prod)",
			input:   "arn:aws:iam::123:role/my-role(prod)",
			want:    true,
		},
		// Plus sign
		{
			name:    "plus sign matches literal",
			pattern: "prefix+suffix",
			input:   "prefix+suffix",
			want:    true,
		},
		{
			name:    "plus sign not treated as regex quantifier",
			pattern: "prefix+suffix",
			input:   "prefixsuffix",
			want:    false,
		},
		// Square brackets
		{
			name:    "brackets match literal",
			pattern: "value[0]",
			input:   "value[0]",
			want:    true,
		},
		{
			name:    "brackets not treated as character class",
			pattern: "value[0]",
			input:   "value0",
			want:    false,
		},
		// Curly braces
		{
			name:    "braces match literal",
			pattern: "name{env}",
			input:   "name{env}",
			want:    true,
		},
		// Caret
		{
			name:    "caret matches literal",
			pattern: "start^end",
			input:   "start^end",
			want:    true,
		},
		// Dollar sign
		{
			name:    "dollar matches literal",
			pattern: "price$100",
			input:   "price$100",
			want:    true,
		},
		// Pipe
		{
			name:    "pipe matches literal",
			pattern: "a|b",
			input:   "a|b",
			want:    true,
		},
		{
			name:    "pipe not treated as alternation - a only",
			pattern: "a|b",
			input:   "a",
			want:    false,
		},
		{
			name:    "pipe not treated as alternation - b only",
			pattern: "a|b",
			input:   "b",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchesPattern(tt.pattern, tt.input)
			assert.Equal(t, tt.want, got, "MatchesPattern(%q, %q)", tt.pattern, tt.input)
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
func TestDeterminePrincipalType(t *testing.T) {
	tests := []struct {
		name     string
		arn      string
		expected PrincipalType
	}{
		{"empty ARN", "", PrincipalTypeUnknown},
		{"invalid ARN", "not-an-arn", PrincipalTypeUnknown},
		{"IAM user", "arn:aws:iam::123456789012:user/alice", PrincipalTypeUser},
		{"IAM role", "arn:aws:iam::123456789012:role/my-role", PrincipalTypeRole},
		{"IAM root", "arn:aws:iam::123456789012:root/account", PrincipalTypeRoot},
		{"STS assumed role", "arn:aws:sts::123456789012:assumed-role/my-role/session", PrincipalTypeRoleSession},
		{"STS federated user", "arn:aws:sts::123456789012:federated-user/my-user", PrincipalTypeFederatedUser},
		{"service principal", "arn:aws:iam:us-east-1:lambda.amazonaws.com:function/my-func", PrincipalTypeService},
		{"canonical user", "arn:aws:iam::123456789012:canonical-user/abc123", PrincipalTypeCanonicalUser},
		{"IAM short resource", "arn:aws:iam::123456789012:policy", PrincipalTypeUnknown},
		{"STS short resource", "arn:aws:sts::123456789012:token", PrincipalTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determinePrincipalType(tt.arn)
			if result != tt.expected {
				t.Errorf("determinePrincipalType(%q) = %q, want %q", tt.arn, result, tt.expected)
			}
		})
	}
}

func TestGetServiceNameFromArn(t *testing.T) {
	tests := []struct {
		name     string
		arn      string
		expected string
	}{
		{"empty ARN", "", ""},
		{"invalid ARN", "not-an-arn", ""},
		{"service in service field", "arn:aws:lambda.amazonaws.com::123456789012:function/my-func", "lambda.amazonaws.com"},
		{"non-service ARN", "arn:aws:iam::123456789012:user/alice", ""},
		// Legacy resource format: service name is in the resource section
		{"legacy format - service in resource", "arn:aws:iam::123456789012:s3.amazonaws.com/bucket", "s3.amazonaws.com"},
		{"legacy format - lambda in resource", "arn:aws:iam::123456789012:lambda.amazonaws.com/function/foo", "lambda.amazonaws.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getServiceNameFromArn(tt.arn)
			if result != tt.expected {
				t.Errorf("getServiceNameFromArn(%q) = %q, want %q", tt.arn, result, tt.expected)
			}
		})
	}
}

func TestNewRequestContext(t *testing.T) {
	ctx := NewRequestContext()
	assert.NotNil(t, ctx)
	assert.NotNil(t, ctx.PrincipalTags)
	assert.NotNil(t, ctx.ResourceTags)
	assert.NotNil(t, ctx.RequestTags)
	assert.NotNil(t, ctx.RequestParameters)
	assert.Empty(t, ctx.PrincipalTags)
	assert.Empty(t, ctx.ResourceTags)
	assert.Empty(t, ctx.RequestTags)
	assert.Empty(t, ctx.RequestParameters)
}

func TestGetUsernameFromArn(t *testing.T) {
	tests := []struct {
		name string
		arn  string
		want string
	}{
		{
			name: "valid user ARN",
			arn:  "arn:aws:iam::123456789012:user/alice",
			want: "alice",
		},
		{
			name: "user ARN with path",
			arn:  "arn:aws:iam::123456789012:user/path/to/bob",
			want: "path/to/bob",
		},
		{
			name: "non-user ARN (role)",
			arn:  "arn:aws:iam::123456789012:role/my-role",
			want: "",
		},
		{
			name: "non-user ARN (group)",
			arn:  "arn:aws:iam::123456789012:group/admins",
			want: "",
		},
		{
			name: "empty ARN",
			arn:  "",
			want: "",
		},
		{
			name: "invalid ARN",
			arn:  "not-an-arn",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getUsernameFromArn(tt.arn)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMatchesPrincipal(t *testing.T) {
	tests := []struct {
		name               string
		principal          *types.Principal
		requestedPrincipal string
		want               bool
	}{
		{
			name:               "nil principal returns false",
			principal:          nil,
			requestedPrincipal: "arn:aws:iam::123456789012:user/alice",
			want:               false,
		},
		{
			name: "Federated principal match",
			principal: &types.Principal{
				Federated: &types.DynaString{"arn:aws:iam::123456789012:oidc-provider/accounts.google.com"},
			},
			requestedPrincipal: "arn:aws:iam::123456789012:oidc-provider/accounts.google.com",
			want:               true,
		},
		{
			name: "Federated principal no match",
			principal: &types.Principal{
				Federated: &types.DynaString{"arn:aws:iam::123456789012:oidc-provider/accounts.google.com"},
			},
			requestedPrincipal: "arn:aws:iam::123456789012:oidc-provider/different-provider",
			want:               false,
		},
		{
			name: "CanonicalUser principal match",
			principal: &types.Principal{
				CanonicalUser: &types.DynaString{"79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"},
			},
			requestedPrincipal: "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be",
			want:               true,
		},
		{
			name: "CanonicalUser principal no match",
			principal: &types.Principal{
				CanonicalUser: &types.DynaString{"79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"},
			},
			requestedPrincipal: "arn:aws:iam::123456789012:user/alice",
			want:               false,
		},
		{
			name: "Service principal match",
			principal: &types.Principal{
				Service: &types.DynaString{"lambda.amazonaws.com"},
			},
			requestedPrincipal: "lambda.amazonaws.com",
			want:               true,
		},
		{
			name: "AWS principal with :root match",
			principal: &types.Principal{
				AWS: &types.DynaString{"arn:aws:iam::123456789012:root"},
			},
			requestedPrincipal: "arn:aws:iam::123456789012:user/alice",
			want:               true,
		},
		{
			name: "empty principal fields returns false",
			principal: &types.Principal{
				// All fields nil
			},
			requestedPrincipal: "arn:aws:iam::123456789012:user/alice",
			want:               false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesPrincipal(tt.principal, tt.requestedPrincipal)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPopulateDefaultRequestConditionKeys_ServicePrincipal(t *testing.T) {
	// Service principal should set ViaAWSService and CalledVia
	// Use an ARN with the service name in the service field so getServiceNameFromArn finds it
	ctx := &RequestContext{
		PrincipalArn: "arn:aws:lambda.amazonaws.com:us-east-1:lambda.amazonaws.com:function/my-func",
	}
	err := ctx.PopulateDefaultRequestConditionKeys("arn:aws:s3::111122223333:my-bucket")
	assert.NoError(t, err)
	assert.NotNil(t, ctx.ViaAWSService)
	assert.True(t, *ctx.ViaAWSService)
	assert.NotEmpty(t, ctx.CalledVia)
	assert.Equal(t, "lambda.amazonaws.com", ctx.CalledVia[0])
}

func TestPopulateDefaultRequestConditionKeys_FederatedUser(t *testing.T) {
	ctx := &RequestContext{
		PrincipalArn: "arn:aws:sts::123456789012:federated-user/my-user",
	}
	err := ctx.PopulateDefaultRequestConditionKeys("arn:aws:s3::111122223333:my-bucket")
	assert.NoError(t, err)
	// FederatedProvider should be set from resource parts
	assert.Equal(t, "federated-user", ctx.FederatedProvider)
}

func TestPopulateDefaultRequestConditionKeys_RoleTokenIssueTime(t *testing.T) {
	ctx := &RequestContext{
		PrincipalArn: "arn:aws:iam::123456789012:role/my-role",
	}
	err := ctx.PopulateDefaultRequestConditionKeys("arn:aws:s3::111122223333:my-bucket")
	assert.NoError(t, err)
	// TokenIssueTime should be set for role principals
	assert.False(t, ctx.TokenIssueTime.IsZero())
}

func TestPopulateDefaultRequestConditionKeys_RoleSessionTokenIssueTime(t *testing.T) {
	ctx := &RequestContext{
		PrincipalArn: "arn:aws:sts::123456789012:assumed-role/my-role/session-name",
	}
	err := ctx.PopulateDefaultRequestConditionKeys("arn:aws:s3::111122223333:my-bucket")
	assert.NoError(t, err)
	// TokenIssueTime should be set for role session principals
	assert.False(t, ctx.TokenIssueTime.IsZero())
}

func TestPopulateDefaultRequestConditionKeys_ZeroCurrentTimeDefaultsToNow(t *testing.T) {
	ctx := &RequestContext{
		PrincipalArn: "arn:aws:iam::123456789012:user/test-user",
		// CurrentTime is zero value
	}
	err := ctx.PopulateDefaultRequestConditionKeys("arn:aws:s3::111122223333:my-bucket")
	assert.NoError(t, err)
	// CurrentTime should be set to approximately now
	assert.False(t, ctx.CurrentTime.IsZero())
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
