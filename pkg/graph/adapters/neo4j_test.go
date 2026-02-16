package adapters

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/graph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewNeo4jAdapter_InvalidURI verifies that empty or malformed URIs are rejected
func TestNewNeo4jAdapter_InvalidURI(t *testing.T) {
	tests := []struct {
		name        string
		uri         string
		expectError bool
	}{
		{
			name:        "empty URI",
			uri:         "",
			expectError: true,
		},
		{
			name:        "valid bolt URI",
			uri:         "bolt://localhost:7687",
			expectError: false,
		},
		{
			name:        "valid neo4j URI",
			uri:         "neo4j://localhost:7687",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := graph.NewConfig(tt.uri, "neo4j", "password")
			adapter, err := NewNeo4jAdapter(cfg)

			if tt.expectError {
				require.Error(t, err, "expected error for invalid URI")
				assert.Nil(t, adapter, "adapter should be nil on error")
			} else {
				require.NoError(t, err, "expected no error for valid URI")
				require.NotNil(t, adapter, "adapter should not be nil")
				if adapter != nil {
					err := adapter.Close()
					assert.NoError(t, err, "Close should not error")
				}
			}
		})
	}
}

// TestNeo4jAdapter_ImplementsInterface verifies compile-time interface compliance
func TestNeo4jAdapter_ImplementsInterface(t *testing.T) {
	// This will fail to compile if Neo4jAdapter doesn't implement GraphDatabase
	var _ graph.GraphDatabase = (*Neo4jAdapter)(nil)
}

// TestNeo4jAdapter_DefaultBatchSize verifies the default batch size is set correctly
func TestNeo4jAdapter_DefaultBatchSize(t *testing.T) {
	cfg := graph.NewConfig("bolt://localhost:7687", "neo4j", "password")
	adapter, err := NewNeo4jAdapter(cfg)
	require.NoError(t, err)
	require.NotNil(t, adapter)
	defer adapter.Close()

	// Verify default batch size is 1000
	assert.Equal(t, 1000, adapter.batchSize, "default batch size should be 1000")
}
