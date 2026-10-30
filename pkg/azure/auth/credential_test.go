package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
)

func TestNewAzureCredential_ReturnsCredentialOrError(t *testing.T) {
	cred, err := NewAzureCredential(azurecloud.Resolve(""))
	if err != nil {
		assert.Nil(t, cred)
		return
	}
	assert.NotNil(t, cred)
}
