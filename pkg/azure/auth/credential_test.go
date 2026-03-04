package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewAzureCredential_ReturnsCredentialOrError(t *testing.T) {
	cred, err := NewAzureCredential()
	if err != nil {
		assert.Nil(t, cred)
		return
	}
	assert.NotNil(t, cred)
}
