package secrets

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

func TestGCPScanAppEngineModule_Metadata(t *testing.T) {
	module := &GCPScanAppEngineModule{}

	assert.Equal(t, "app-engine-secrets", module.ID())
	assert.Equal(t, "GCP Scan App Engine Secrets", module.Name())
	assert.Equal(t, "List all App Engine applications in a GCP project and scan them for secrets.", module.Description())
	assert.Equal(t, plugin.PlatformGCP, module.Platform())
	assert.Equal(t, plugin.CategorySecrets, module.Category())
	assert.Equal(t, "moderate", module.OpsecLevel())
	assert.Equal(t, []string{"Praetorian"}, module.Authors())
	assert.Empty(t, module.References())
}

func TestGCPScanAppEngineModule_Parameters(t *testing.T) {
	module := &GCPScanAppEngineModule{}
	params := module.Parameters()

	assert.Len(t, params, 2)
	assert.Equal(t, "project", params[0].Name)
	assert.True(t, params[0].Required)
	assert.Equal(t, "creds-file", params[1].Name)
	assert.False(t, params[1].Required)
}

func TestGCPScanAppEngineModule_Run_MissingProject(t *testing.T) {
	module := &GCPScanAppEngineModule{}
	cfg := plugin.Config{
		Args:    map[string]any{},
		Context: context.Background(),
	}

	results, err := module.Run(cfg)
	assert.Error(t, err)
	assert.Nil(t, results)
	assert.Contains(t, err.Error(), "project parameter is required")
}
