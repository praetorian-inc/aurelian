package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

func TestGCPResourcePoliciesModule_Metadata(t *testing.T) {
	m := &GCPResourcePoliciesModule{}
	assert.Equal(t, "resource-policies", m.ID())
	assert.Equal(t, "GCP Resource IAM Policies", m.Name())
	assert.Equal(t, plugin.PlatformGCP, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "moderate", m.OpsecLevel())
	assert.NotNil(t, m.Parameters())
}
