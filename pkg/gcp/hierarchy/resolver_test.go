package hierarchy

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

func TestIsSystemProject(t *testing.T) {
	assert.True(t, plugin.IsSystemProject("sys-12345"))
	assert.True(t, plugin.IsSystemProject("script-editor-abc"))
	assert.True(t, plugin.IsSystemProject("apps-script-xyz"))
	assert.False(t, plugin.IsSystemProject("my-production-project"))
}

func TestNewResolver(t *testing.T) {
	opts := plugin.GCPCommonRecon{Concurrency: 5}
	r := NewResolver(opts)
	assert.NotNil(t, r)
}

func TestExtractID(t *testing.T) {
	assert.Equal(t, "123456", extractID("organizations/123456"))
	assert.Equal(t, "789", extractID("folders/789"))
	assert.Equal(t, "plain", extractID("plain"))
}
