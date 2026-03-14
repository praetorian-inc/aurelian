//go:build integration

package recon

import (
	"testing"

	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon" // register modules
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWhoamiExtractsCallerARN(t *testing.T) {
	fixture := testutil.NewFixture(t, "aws/recon/whoami")
	fixture.Setup()

	expectedAccount := fixture.Output("account_id")
	expectedARN := fixture.Output("arn")

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "whoami")
	if !ok {
		t.Skip("whoami module not registered in plugin system")
	}

	results, err := testutil.RunAndCollect(t, mod, plugin.Config{
		Args: map[string]any{
			"action": "all",
		},
	})
	require.NoError(t, err)
	testutil.AssertMinResults(t, results, 1)

	identity, ok := results[0].(*output.CallerIdentity)
	require.True(t, ok, "result should be *output.CallerIdentity")

	if identity.Status == "success" {
		assert.Equal(t, expectedAccount, identity.Account, "account should match")
		assert.Contains(t, identity.ARN, expectedAccount, "ARN should contain the account ID")

		if identity.ARN != expectedARN {
			t.Logf("ARN mismatch (may be expected for assumed roles): got=%s want=%s", identity.ARN, expectedARN)
		}
	} else {
		assert.Equal(t, "no_arn_found", identity.Status)
		t.Log("covert whoami returned no_arn_found — caller has permissions on all probe APIs")
	}
}

func TestWhoamiSingleTechnique(t *testing.T) {
	fixture := testutil.NewFixture(t, "aws/recon/whoami")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "whoami")
	if !ok {
		t.Skip("whoami module not registered in plugin system")
	}

	techniques := []string{"sns", "sqs"}
	for _, technique := range techniques {
		t.Run(technique, func(t *testing.T) {
			results, err := testutil.RunAndCollect(t, mod, plugin.Config{
				Args: map[string]any{
					"action": technique,
				},
			})
			require.NoError(t, err)
			require.Len(t, results, 1)

			identity, ok := results[0].(*output.CallerIdentity)
			require.True(t, ok, "result should be *output.CallerIdentity")

			if identity.Status == "success" {
				assert.NotEmpty(t, identity.ARN)
				assert.NotEmpty(t, identity.Account)
			}
		})
	}
}
