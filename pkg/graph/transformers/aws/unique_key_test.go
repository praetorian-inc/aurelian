package aws

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNodeFromAWSResource_UniqueKeyMatchesProperty verifies that the UniqueKey
// references a property that actually exists in the node's Properties map.
// This prevents Neo4j errors like "Cannot merge node because of null property value for 'ARN'"
func TestNodeFromAWSResource_UniqueKeyMatchesProperty(t *testing.T) {
	resource := output.AWSResource{
		ResourceType: "AWS::S3::Bucket",
		ResourceID:   "test-bucket",
		ARN:          "arn:aws:s3:::test-bucket",
		AccountRef:   "123456789012",
		Region:       "us-east-1",
	}

	node := NodeFromAWSResource(resource)

	require.NotNil(t, node)
	require.NotEmpty(t, node.UniqueKey, "UniqueKey must not be empty")

	// CRITICAL: Verify that each key in UniqueKey exists in Properties
	for _, key := range node.UniqueKey {
		value, exists := node.Properties[key]
		assert.True(t, exists,
			"UniqueKey references '%s' but it doesn't exist in Properties (available keys: %v)",
			key, getPropertyKeys(node.Properties))
		assert.NotNil(t, value,
			"UniqueKey references '%s' but its value is nil", key)

		// If the key is for ARN, verify it's the correct value
		if key == "arn" {
			assert.Equal(t, resource.ARN, value,
				"Property '%s' should match resource ARN", key)
		}
	}
}

// getPropertyKeys returns the keys from a properties map for debugging
func getPropertyKeys(props map[string]interface{}) []string {
	keys := make([]string, 0, len(props))
	for k := range props {
		keys = append(keys, k)
	}
	return keys
}
