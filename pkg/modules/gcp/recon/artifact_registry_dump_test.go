package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

func TestGCPArtifactRegistryDumpModule_Metadata(t *testing.T) {
	m := &GCPArtifactRegistryDumpModule{}
	assert.Equal(t, "artifact-registry-dump", m.ID())
	assert.Equal(t, "GCP Artifact Registry Dump", m.Name())
	assert.Equal(t, plugin.PlatformGCP, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "moderate", m.OpsecLevel())
	assert.NotNil(t, m.Parameters())
}
