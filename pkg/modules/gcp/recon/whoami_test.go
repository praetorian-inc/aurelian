package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

func TestGCPWhoamiModule_Metadata(t *testing.T) {
	m := &GCPWhoamiModule{}
	assert.Equal(t, "whoami", m.ID())
	assert.Equal(t, "GCP Covert Whoami", m.Name())
	assert.Equal(t, plugin.PlatformGCP, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "stealth", m.OpsecLevel())
	assert.NotNil(t, m.Parameters())
}
