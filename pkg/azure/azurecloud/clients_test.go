package azurecloud_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
)

func TestARMClientOptionsRejectsUnresolvedEnvironment(t *testing.T) {
	assert.Panics(t, func() { azurecloud.ARMClientOptions(azurecloud.Environment{}) })
}
