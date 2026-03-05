package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

func TestGCPPublicResourcesModule_Metadata(t *testing.T) {
	m := &GCPPublicResourcesModule{}
	assert.Equal(t, "public-resources", m.ID())
	assert.Equal(t, plugin.PlatformGCP, m.Platform())
	// Should have fewer supported types than list-all
	assert.Less(t, len(m.SupportedResourceTypes()), len(allResourceTypes()))
}
