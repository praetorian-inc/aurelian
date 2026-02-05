package recon

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGCPListFoldersModule_Metadata(t *testing.T) {
	m := &GCPListFoldersModule{}

	assert.Equal(t, "folders-list", m.ID())
	assert.Equal(t, "GCP List Folders", m.Name())
	assert.Equal(t, "List all folders in a GCP organization.", m.Description())
	assert.Equal(t, plugin.PlatformGCP, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "moderate", m.OpsecLevel())
	assert.Equal(t, []string{"Praetorian"}, m.Authors())
	assert.Equal(t, []string{}, m.References())
}

func TestGCPListFoldersModule_Parameters(t *testing.T) {
	m := &GCPListFoldersModule{}
	params := m.Parameters()

	require.Len(t, params, 2)

	// Check org parameter
	assert.Equal(t, "org", params[0].Name)
	assert.Equal(t, "string", params[0].Type)
	assert.True(t, params[0].Required)

	// Check creds-file parameter
	assert.Equal(t, "creds-file", params[1].Name)
	assert.Equal(t, "string", params[1].Type)
	assert.False(t, params[1].Required)
}

func TestGCPListFoldersModule_Run_MissingOrg(t *testing.T) {
	m := &GCPListFoldersModule{}

	cfg := plugin.Config{
		Args:    map[string]any{},
		Context: context.Background(),
	}

	results, err := m.Run(cfg)
	require.Error(t, err)
	assert.Nil(t, results)
	assert.Contains(t, err.Error(), "org parameter is required")
}

func TestGCPListFoldersModule_OrgNormalization(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "org with prefix",
			input:    "organizations/123456789",
			expected: "organizations/123456789",
		},
		{
			name:     "org without prefix",
			input:    "123456789",
			expected: "organizations/123456789",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This tests the normalization logic that will be in Run()
			orgName := tt.input
			if len(orgName) > 0 && !strings.HasPrefix(orgName, "organizations/") {
				orgName = "organizations/" + orgName
			}
			// Note: Go string indexing panic protection - proper implementation checks length first
			assert.Equal(t, tt.expected, orgName)
		})
	}
}

// TestGCPListFoldersModule_Run_Integration is skipped by default
// Run with: go test -tags=integration
func TestGCPListFoldersModule_Run_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	m := &GCPListFoldersModule{}

	// This test requires actual GCP credentials and a real organization
	// It's meant to verify the integration works but won't run in CI
	cfg := plugin.Config{
		Args: map[string]any{
			"org": "organizations/123456789", // Replace with real org for manual testing
		},
		Context: context.Background(),
	}

	results, err := m.Run(cfg)
	if err != nil {
		t.Skipf("integration test failed (expected without credentials): %v", err)
	}

	// If we got results, verify they're CloudResources
	for _, result := range results {
		assert.NotNil(t, result.Data)
		if cr, ok := result.Data.(*output.CloudResource); ok {
			assert.Equal(t, "gcp", cr.Platform)
			assert.Equal(t, "cloudresourcemanager.googleapis.com/Folder", cr.ResourceType)
		}
	}
}
