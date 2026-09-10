package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

func TestGCPPrivescDetectionModule_Metadata(t *testing.T) {
	m := &GCPPrivescDetectionModule{}
	assert.Equal(t, "privesc-detection", m.ID())
	assert.Equal(t, "GCP Privilege Escalation Detection", m.Name())
	assert.Equal(t, plugin.PlatformGCP, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "stealth", m.OpsecLevel())
	assert.NotEmpty(t, m.Description())
	assert.NotEmpty(t, m.References())
	assert.NotEmpty(t, m.Authors())
}

func TestPrivescDetection_SupportedResourceTypes(t *testing.T) {
	m := &GCPPrivescDetectionModule{}
	types := m.SupportedResourceTypes()
	expected := []string{
		"cloudresourcemanager.googleapis.com/Organization",
		"cloudresourcemanager.googleapis.com/Folder",
		"cloudresourcemanager.googleapis.com/Project",
	}
	assert.ElementsMatch(t, expected, types)
}

func TestPrivescDetection_Parameters(t *testing.T) {
	m := &GCPPrivescDetectionModule{}
	params := m.Parameters()
	assert.NotNil(t, params)
	_, ok := params.(*GCPPrivescDetectionConfig)
	assert.True(t, ok)
}
