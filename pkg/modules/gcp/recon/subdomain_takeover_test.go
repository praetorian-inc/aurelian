package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

func TestGCPSubdomainTakeoverModule_Metadata(t *testing.T) {
	m := &GCPSubdomainTakeoverModule{}
	assert.Equal(t, "subdomain-takeover", m.ID())
	assert.Equal(t, plugin.PlatformGCP, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.NotNil(t, m.Parameters())
}

func TestGCPSubdomainTakeover_SupportedResourceTypes(t *testing.T) {
	m := &GCPSubdomainTakeoverModule{}
	types := m.SupportedResourceTypes()
	expected := append([]string{
		"cloudresourcemanager.googleapis.com/Organization",
		"cloudresourcemanager.googleapis.com/Folder",
		"cloudresourcemanager.googleapis.com/Project",
	}, subdomainTakeoverResourceTypes...)
	assert.ElementsMatch(t, expected, types)
}
