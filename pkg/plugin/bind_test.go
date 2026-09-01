package plugin_test

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type bindTarget struct {
	Checkpoint string `param:"checkpoint"`
	Mode       string `param:"mode" default:"latest"`
	Depth      int    `param:"depth" default:"3"`
	Verbose    bool   `param:"verbose"`
	Untagged   string `param:"-"`
}

// Registry modules are singletons: the same Parameters struct is bound before
// every Run. A parameter that is absent from cfg.Args and has no default must
// therefore RESET its field, otherwise a value from one run leaks into the next
// — e.g. an ecr-dump --modified-since checkpoint suppressing a later full scan.
func TestBind_ClearsParamsAbsentFromArgs(t *testing.T) {
	target := &bindTarget{}

	require.NoError(t, plugin.Bind(plugin.Config{Args: map[string]any{
		"checkpoint": "2026-08-01T00:00:00Z",
		"mode":       "all",
		"verbose":    true,
	}}, target))
	require.Equal(t, "2026-08-01T00:00:00Z", target.Checkpoint)
	require.Equal(t, "all", target.Mode)
	require.True(t, target.Verbose)

	// Second bind, as a second Run would do, supplying none of them.
	require.NoError(t, plugin.Bind(plugin.Config{Args: map[string]any{}}, target))

	assert.Empty(t, target.Checkpoint,
		"a param with no value and no default must be cleared, not carried over from the previous Bind")
	assert.False(t, target.Verbose,
		"a bool param absent from Args must fall back to false, not stay true")
	assert.Equal(t, "latest", target.Mode, "a param with a default must fall back to that default")
	assert.Equal(t, 3, target.Depth)
}

// Fields opted out with `param:"-"` are outside Bind's remit and must be left alone.
func TestBind_LeavesOptedOutFieldsAlone(t *testing.T) {
	target := &bindTarget{Untagged: "set by the caller"}

	require.NoError(t, plugin.Bind(plugin.Config{}, target))

	assert.Equal(t, "set by the caller", target.Untagged)
}

func TestBind_AppliesDefaultsOnFirstBind(t *testing.T) {
	target := &bindTarget{}

	require.NoError(t, plugin.Bind(plugin.Config{}, target))

	assert.Equal(t, "latest", target.Mode)
	assert.Equal(t, 3, target.Depth)
	assert.Empty(t, target.Checkpoint)
	assert.False(t, target.Verbose)
}
