package queries

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestQueryMetadata_YAMLParsing(t *testing.T) {
	yamlContent := `id: aws/enrich/privesc/method_01
name: IAM CreatePolicyVersion Privilege Escalation
platform: aws
type: enrich
category: privesc
description: Detects principals with iam:CreatePolicyVersion
severity: high
order: 1
cypher: |
  MATCH (attacker:Principal)-[perm]->(policy:Policy)
  WHERE perm.action CONTAINS 'iam:CreatePolicyVersion'
  MERGE (attacker)-[privesc:CAN_PRIVESC]->(victim)
parameters:
  - account_id
`

	var metadata QueryMetadata
	err := yaml.Unmarshal([]byte(yamlContent), &metadata)
	require.NoError(t, err, "Should unmarshal valid YAML without error")

	// Verify all fields populated correctly
	assert.Equal(t, "aws/enrich/privesc/method_01", metadata.ID)
	assert.Equal(t, "IAM CreatePolicyVersion Privilege Escalation", metadata.Name)
	assert.Equal(t, "aws", metadata.Platform)
	assert.Equal(t, "enrich", metadata.Type)
	assert.Equal(t, "privesc", metadata.Category)
	assert.Equal(t, "Detects principals with iam:CreatePolicyVersion", metadata.Description)
	assert.Equal(t, "high", metadata.Severity)
	assert.Equal(t, 1, metadata.Order)
	assert.Contains(t, metadata.Cypher, "MATCH (attacker:Principal)")
	assert.Contains(t, metadata.Cypher, "iam:CreatePolicyVersion")
	assert.Len(t, metadata.Parameters, 1)
	assert.Equal(t, "account_id", metadata.Parameters[0])
}

func TestQueryMetadata_Defaults(t *testing.T) {
	// Zero-value struct should have empty strings and 0 order
	var metadata QueryMetadata

	assert.Equal(t, "", metadata.ID)
	assert.Equal(t, "", metadata.Name)
	assert.Equal(t, "", metadata.Platform)
	assert.Equal(t, "", metadata.Type)
	assert.Equal(t, "", metadata.Category)
	assert.Equal(t, "", metadata.Description)
	assert.Equal(t, "", metadata.Severity)
	assert.Equal(t, 0, metadata.Order)
	assert.Equal(t, "", metadata.Cypher)
	assert.Nil(t, metadata.Parameters)
}

func TestQuery_CypherFromMetadata(t *testing.T) {
	metadata := QueryMetadata{
		ID:          "test/query/001",
		Name:        "Test Query",
		Platform:    "aws",
		Type:        "enrich",
		Category:    "test",
		Description: "Test description",
		Severity:    "low",
		Order:       10,
		Cypher:      "MATCH (n) RETURN n",
		Parameters:  []string{"param1", "param2"},
	}

	query := Query{
		Metadata: metadata,
		Cypher:   metadata.Cypher,
	}

	assert.Equal(t, "test/query/001", query.Metadata.ID)
	assert.Equal(t, "MATCH (n) RETURN n", query.Cypher)
	assert.Equal(t, metadata.Cypher, query.Cypher)
}

func TestQueryMetadata_MinimalYAML(t *testing.T) {
	// Test minimal YAML with only required fields
	yamlContent := `id: minimal/query
name: Minimal Query
platform: aws
type: analysis
category: test
description: Minimal test
severity: low
order: 1
cypher: "MATCH (n) RETURN n"
`

	var metadata QueryMetadata
	err := yaml.Unmarshal([]byte(yamlContent), &metadata)
	require.NoError(t, err)

	assert.Equal(t, "minimal/query", metadata.ID)
	assert.Equal(t, "Minimal Query", metadata.Name)
	assert.Empty(t, metadata.Parameters, "Parameters should be empty when not provided")
}

func TestQueryMetadata_MultilineYAML(t *testing.T) {
	// Test multiline Cypher query with proper formatting
	yamlContent := `id: multiline/test
name: Multiline Test
platform: azure
type: enrich
category: resource-to-role
description: Tests multiline Cypher
severity: medium
order: 5
cypher: |
  MATCH (resource:Resource)-[:HAS_PERMISSION]->(role:Role)
  WHERE role.name CONTAINS 'Admin'
  AND resource.public = true
  RETURN resource, role
parameters:
  - subscription_id
  - resource_group
`

	var metadata QueryMetadata
	err := yaml.Unmarshal([]byte(yamlContent), &metadata)
	require.NoError(t, err)

	assert.Equal(t, "multiline/test", metadata.ID)
	assert.Contains(t, metadata.Cypher, "MATCH (resource:Resource)")
	assert.Contains(t, metadata.Cypher, "WHERE role.name CONTAINS 'Admin'")
	assert.Contains(t, metadata.Cypher, "RETURN resource, role")
	assert.Len(t, metadata.Parameters, 2)
	assert.Contains(t, metadata.Parameters, "subscription_id")
	assert.Contains(t, metadata.Parameters, "resource_group")
}
