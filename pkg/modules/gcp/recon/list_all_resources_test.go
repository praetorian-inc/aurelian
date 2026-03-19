package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

func TestGCPListAllResourcesModule_Metadata(t *testing.T) {
	m := &GCPListAllResourcesModule{}
	assert.Equal(t, "list-all", m.ID())
	assert.Equal(t, plugin.PlatformGCP, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.NotNil(t, m.Parameters())
}

func TestListAllResources_SupportedResourceTypes(t *testing.T) {
	m := &GCPListAllResourcesModule{}
	types := m.SupportedResourceTypes()
	expected := []string{
		"cloudresourcemanager.googleapis.com/Organization",
		"cloudresourcemanager.googleapis.com/Folder",
		"cloudresourcemanager.googleapis.com/Project",
	}
	assert.ElementsMatch(t, expected, types)
}
