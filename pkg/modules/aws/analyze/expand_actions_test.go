package analyze

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var knownActions = []string{
	"s3:GetObject",
	"s3:GetObjectAcl",
	"s3:PutObject",
	"s3:DeleteObject",
	"s3:ListBucket",
	"ec2:DescribeInstances",
	"ec2:StartInstances",
	"ec2:StopInstances",
	"iam:GetUser",
	"iam:ListUsers",
}

func TestExpandActionPattern_ExactMatch(t *testing.T) {
	matches, err := expandActionPattern("s3:GetObject", knownActions)
	require.NoError(t, err)
	assert.Equal(t, []string{"s3:GetObject"}, matches)
}

func TestExpandActionPattern_WildcardAtEnd(t *testing.T) {
	matches, err := expandActionPattern("s3:Get*", knownActions)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"s3:GetObject", "s3:GetObjectAcl"}, matches)
}

func TestExpandActionPattern_FullWildcard(t *testing.T) {
	matches, err := expandActionPattern("*", knownActions)
	require.NoError(t, err)
	assert.ElementsMatch(t, knownActions, matches)
}

func TestExpandActionPattern_CaseInsensitive(t *testing.T) {
	matches, err := expandActionPattern("S3:get*", knownActions)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"s3:GetObject", "s3:GetObjectAcl"}, matches)
}

func TestExpandActionPattern_MultipleWildcards(t *testing.T) {
	matches, err := expandActionPattern("s3:*Object*", knownActions)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"s3:GetObject", "s3:GetObjectAcl", "s3:PutObject", "s3:DeleteObject"}, matches)
}

func TestExpandActionPattern_NoMatches(t *testing.T) {
	matches, err := expandActionPattern("nonexistent:*", knownActions)
	require.NoError(t, err)
	assert.Empty(t, matches)
}

func TestExpandActionPattern_EmptyInputList(t *testing.T) {
	matches, err := expandActionPattern("s3:Get*", []string{})
	require.NoError(t, err)
	assert.Empty(t, matches)
}

func TestExpandActionPattern_ServicePrefixWildcard(t *testing.T) {
	matches, err := expandActionPattern("ec2:*Instances", knownActions)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"ec2:DescribeInstances", "ec2:StartInstances", "ec2:StopInstances"}, matches)
}

func TestExpandActionPattern_ExactMatchNotFound(t *testing.T) {
	matches, err := expandActionPattern("s3:HeadObject", knownActions)
	require.NoError(t, err)
	assert.Empty(t, matches)
}

func TestExpandActionPattern_FullWildcardPreservesAll(t *testing.T) {
	// Full wildcard returns a copy; verify length and contents match
	matches, err := expandActionPattern("*", knownActions)
	require.NoError(t, err)
	assert.Len(t, matches, len(knownActions))
	// Verify it's a copy, not the same slice
	matches[0] = "mutated"
	assert.NotEqual(t, "mutated", knownActions[0])
}
