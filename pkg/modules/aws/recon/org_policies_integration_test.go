//go:build integration

package recon

import (
	"context"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/require"
)

func TestAWSOrgPolicies(t *testing.T) {
	t.Skip("skipping until we resolve the permissions issues")

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "org-policies")
	if !ok {
		t.Skip("org-policies module not registered in plugin system")
	}

	results, err := mod.Run(plugin.Config{
		Context: context.Background(),
	})
	require.NoError(t, err)
	testutil.AssertMinResults(t, results, 1)
}
