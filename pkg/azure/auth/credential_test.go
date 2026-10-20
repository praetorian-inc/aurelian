package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/aurelian/test/azuretest"
)

func TestNewAzureCredential_ReturnsCredentialOrError(t *testing.T) {
	_, env := azuretest.NewCredential(t, "public")
	cred, err := NewAzureCredential(env)
	if err != nil {
		assert.Nil(t, cred)
		return
	}
	assert.NotNil(t, cred)
}
