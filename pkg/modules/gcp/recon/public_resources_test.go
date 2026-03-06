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
}

func TestPublicResources_SupportedResourceTypes(t *testing.T) {
	m := &GCPPublicResourcesModule{}
	types := m.SupportedResourceTypes()
	expected := []string{
		"cloudresourcemanager.googleapis.com/Organization",
		"cloudresourcemanager.googleapis.com/Folder",
		"cloudresourcemanager.googleapis.com/Project",
	}
	assert.ElementsMatch(t, expected, types)
}
