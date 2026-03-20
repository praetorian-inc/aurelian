package iamadmin

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stretchr/testify/assert"
)

func TestHasAdministratorAccessPolicy(t *testing.T) {
	assert.True(t, hasAdministratorAccessPolicy([]types.AttachedPolicy{
		{PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess")},
	}))

	assert.False(t, hasAdministratorAccessPolicy([]types.AttachedPolicy{
		{PolicyArn: aws.String("arn:aws:iam::aws:policy/ReadOnlyAccess")},
	}))

	assert.False(t, hasAdministratorAccessPolicy(nil))
}

func TestPolicyDocumentHasAdminWildcardStatement(t *testing.T) {
	assert.True(t, policyDocumentHasAdminWildcardStatement(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`))
	assert.False(t, policyDocumentHasAdminWildcardStatement(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}`))
	assert.False(t, policyDocumentHasAdminWildcardStatement("{not-json"))
	assert.False(t, policyDocumentHasAdminWildcardStatement(""))
}

func TestStatementIsAdminWildcard(t *testing.T) {
	tests := []struct {
		name     string
		stmt     map[string]any
		expected bool
	}{
		{
			name:     "full wildcard admin",
			stmt:     map[string]any{"Effect": "Allow", "Action": "*", "Resource": "*"},
			expected: true,
		},
		{
			name:     "action and resource as lists containing wildcard",
			stmt:     map[string]any{"Effect": "Allow", "Action": []any{"*"}, "Resource": []any{"*"}},
			expected: true,
		},
		{
			name:     "wildcard among other actions",
			stmt:     map[string]any{"Effect": "Allow", "Action": []any{"s3:GetObject", "*"}, "Resource": "*"},
			expected: true,
		},
		{
			name:     "wildcard among other resources",
			stmt:     map[string]any{"Effect": "Allow", "Action": "*", "Resource": []any{"arn:aws:s3:::bucket", "*"}},
			expected: true,
		},
		{
			name:     "effect is case insensitive",
			stmt:     map[string]any{"Effect": "allow", "Action": "*", "Resource": "*"},
			expected: true,
		},
		{
			name:     "deny effect",
			stmt:     map[string]any{"Effect": "Deny", "Action": "*", "Resource": "*"},
			expected: false,
		},
		{
			name:     "missing effect",
			stmt:     map[string]any{"Action": "*", "Resource": "*"},
			expected: false,
		},
		{
			name:     "scoped action",
			stmt:     map[string]any{"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
			expected: false,
		},
		{
			name:     "scoped resource",
			stmt:     map[string]any{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::bucket/*"},
			expected: false,
		},
		{
			name:     "action list without wildcard",
			stmt:     map[string]any{"Effect": "Allow", "Action": []any{"s3:GetObject", "ec2:Describe*"}, "Resource": "*"},
			expected: false,
		},
		{
			name:     "resource list without wildcard",
			stmt:     map[string]any{"Effect": "Allow", "Action": "*", "Resource": []any{"arn:aws:s3:::a", "arn:aws:s3:::b"}},
			expected: false,
		},
		{
			name:     "missing action key",
			stmt:     map[string]any{"Effect": "Allow", "Resource": "*"},
			expected: false,
		},
		{
			name:     "missing resource key",
			stmt:     map[string]any{"Effect": "Allow", "Action": "*"},
			expected: false,
		},
		{
			name:     "empty statement",
			stmt:     map[string]any{},
			expected: false,
		},
		{
			name:     "numeric action value",
			stmt:     map[string]any{"Effect": "Allow", "Action": 42, "Resource": "*"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, statementIsAdminWildcard(tt.stmt))
		})
	}
}
