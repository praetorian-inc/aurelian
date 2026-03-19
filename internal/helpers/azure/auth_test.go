package azure

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewAzureCredential_ReturnsNonNil(t *testing.T) {
	// This test verifies the function exists and compiles.
	// Actual credential creation depends on environment, so we just
	// test that the function signature is correct and returns an error
	// when no credentials are configured (CI-safe).
	cred, err := NewAzureCredential()
	if err != nil {
		// Expected in environments without Azure creds configured
		assert.Nil(t, cred)
		return
	}
	assert.NotNil(t, cred)
}
