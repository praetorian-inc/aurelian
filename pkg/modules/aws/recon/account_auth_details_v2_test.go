package recon

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewGetAccountAuthDetailsV2 tests that the constructor creates a properly initialized instance
func TestNewGetAccountAuthDetailsV2(t *testing.T) {
	profile := "test-profile"

	getter := NewGetAccountAuthDetailsV2(profile)

	require.NotNil(t, getter)
	assert.Equal(t, profile, getter.Profile)
	assert.Equal(t, "us-east-1", getter.Region, "Region should default to us-east-1 (IAM is global)")
}

// TestReplaceURLEncodedPoliciesV2 tests URL decoding of policy documents
func TestReplaceURLEncodedPoliciesV2(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "decodes URL-encoded policy document",
			input:    `{"PolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%5D%7D"}`,
			expected: `{"PolicyDocument":{"Version":"2012-10-17","Statement":[]}}`,
			wantErr:  false,
		},
		{
			name:     "leaves non-encoded strings unchanged",
			input:    `{"PolicyName": "test-policy"}`,
			expected: `{"PolicyName":"test-policy"}`,
			wantErr:  false,
		},
		{
			name:     "handles nested objects",
			input:    `{"User": {"Name": "test", "PolicyDocument": "%7B%22Version%22%3A%222012-10-17%22%7D"}}`,
			expected: `{"User":{"Name":"test","PolicyDocument":{"Version":"2012-10-17"}}}`,
			wantErr:  false,
		},
		{
			name:     "handles arrays",
			input:    `{"Policies": [{"Document": "%7B%22Statement%22%3A%5B%5D%7D"}]}`,
			expected: `{"Policies":[{"Document":{"Statement":[]}}]}`,
			wantErr:  false,
		},
		{
			name:     "invalid JSON returns error",
			input:    `{invalid json}`,
			expected: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := replaceURLEncodedPoliciesV2([]byte(tt.input))

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			// Normalize JSON for comparison (remove whitespace differences)
			var expectedJSON, resultJSON interface{}
			require.NoError(t, json.Unmarshal([]byte(tt.expected), &expectedJSON))
			require.NoError(t, json.Unmarshal(result, &resultJSON))

			assert.Equal(t, expectedJSON, resultJSON)
		})
	}
}

// TestGetAccountAuthDetailsV2_Run_Integration is an integration test that requires AWS credentials
// It is skipped in CI/CD environments
func TestGetAccountAuthDetailsV2_Run_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// This test would require actual AWS credentials and should be run manually
	t.Skip("Integration test - requires AWS credentials")

	ctx := context.Background()
	getter := NewGetAccountAuthDetailsV2("default")

	result, err := getter.Run(ctx)
	require.NoError(t, err)

	// Verify basic structure
	assert.NotNil(t, result)
}
