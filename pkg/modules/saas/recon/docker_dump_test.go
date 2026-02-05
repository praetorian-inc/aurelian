package recon

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDockerDump_Interface(t *testing.T) {
	module := &DockerDump{}

	// Verify it implements plugin.Module
	var _ plugin.Module = module

	// Test metadata methods
	assert.Equal(t, "docker-dump", module.ID())
	assert.Equal(t, "Docker Container Dumper", module.Name())
	assert.NotEmpty(t, module.Description())
	assert.Equal(t, plugin.PlatformSaaS, module.Platform())
	assert.Equal(t, plugin.CategoryRecon, module.Category())
	assert.Equal(t, "none", module.OpsecLevel())
	assert.Contains(t, module.Authors(), "Praetorian")
}

func TestDockerDump_Parameters(t *testing.T) {
	module := &DockerDump{}
	params := module.Parameters()

	// Should have docker-image parameter
	var hasDockerImage bool
	for _, p := range params {
		if p.Name == "docker-image" {
			hasDockerImage = true
			assert.Equal(t, "string", p.Type)
			assert.True(t, p.Required)
		}
	}
	assert.True(t, hasDockerImage, "should have docker-image parameter")
}

func TestDockerDump_Run_MissingDockerImage(t *testing.T) {
	module := &DockerDump{}

	cfg := plugin.Config{
		Args:    map[string]any{},
		Context: context.Background(),
	}

	results, err := module.Run(cfg)
	require.Error(t, err)
	assert.Nil(t, results)
	assert.Contains(t, err.Error(), "docker-image")
}
