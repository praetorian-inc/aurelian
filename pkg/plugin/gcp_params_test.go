package plugin_test

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

func TestGCPCommonRecon_PostBind_SetsClientOptions(t *testing.T) {
	c := plugin.GCPCommonRecon{CredentialsFile: "/tmp/creds.json", ProjectID: []string{"my-project"}, Concurrency: 5}
	err := c.PostBind(plugin.Config{}, nil)
	assert.NoError(t, err)
	assert.Len(t, c.ClientOptions, 1)
}

func TestGCPCommonRecon_PostBind_NoCredsFile(t *testing.T) {
	c := plugin.GCPCommonRecon{ProjectID: []string{"my-project"}, Concurrency: 3}
	err := c.PostBind(plugin.Config{}, nil)
	assert.NoError(t, err)
	assert.Empty(t, c.ClientOptions)
}

func TestGCPCommonRecon_PostBind_ClampsMinConcurrency(t *testing.T) {
	c := plugin.GCPCommonRecon{ProjectID: []string{"my-project"}, Concurrency: 0}
	err := c.PostBind(plugin.Config{}, nil)
	assert.NoError(t, err)
	assert.Equal(t, 1, c.Concurrency)
}

func TestGCPCommonRecon_PostBind_NoScopeError(t *testing.T) {
	c := plugin.GCPCommonRecon{Concurrency: 5}
	err := c.PostBind(plugin.Config{}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one of --project-id, --org-id, or --folder-id")
}
