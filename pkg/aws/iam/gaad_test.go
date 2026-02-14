package iam

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RED: Test decodeURLEncodedPolicies decodes URL-encoded JSON
func TestDecodeURLEncodedPolicies(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "decodes URL-encoded policy",
			input:   `{"PolicyDocument":"%7B%22Version%22%3A%222012-10-17%22%7D"}`,
			wantErr: false,
		},
		{
			name:    "handles non-encoded data",
			input:   `{"PolicyDocument":{"Version":"2012-10-17"}}`,
			wantErr: false,
		},
		{
			name:    "handles invalid JSON",
			input:   `{invalid}`,
			wantErr: true,
		},
		{
			name:    "decodes nested policy documents",
			input:   `{"Role":{"AssumeRolePolicyDocument":"%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%7D%5D%7D"}}`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := decodeURLEncodedPolicies([]byte(tt.input))
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, result)
			}
		})
	}
}

// RED: Test decodeURLEncodedPolicies preserves structure
func TestDecodeURLEncodedPolicies_PreservesStructure(t *testing.T) {
	input := `{"Users":[{"UserPolicyList":[{"PolicyName":"test","PolicyDocument":"%7B%22Version%22%3A%222012-10-17%22%7D"}]}]}`
	result, err := decodeURLEncodedPolicies([]byte(input))

	require.NoError(t, err)
	assert.Contains(t, string(result), "Version")
	assert.Contains(t, string(result), "2012-10-17")
	assert.NotContains(t, string(result), "%7B") // Should not contain URL-encoded characters
}
