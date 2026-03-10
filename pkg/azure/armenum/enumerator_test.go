package armenum

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// TestARMEnumerator_List_NilCred verifies List returns nil (not panic) when
// the ARM client calls fail with an auth error. handleListError suppresses auth failures.
func TestARMEnumerator_List_NilCred(t *testing.T) {
	e := NewARMEnumerator(nil)
	sub := azuretypes.SubscriptionInfo{ID: "00000000-0000-0000-0000-000000000000"}

	out := pipeline.New[output.AzureResource]()
	go func() {
		defer out.Close()
		err := e.List(sub, out)
		// All auth errors are swallowed by handleListError; nil expected.
		assert.NoError(t, err)
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	// No real Azure connection: expect empty result, not a panic.
	assert.Empty(t, items)
}

func TestARMEnumerator_ResourceTypesConstant(t *testing.T) {
	// Ensure the documented resource types match what the extractors expect.
	expected := []string{
		"Microsoft.Resources/deployments",
		"Microsoft.Authorization/policyDefinitions",
		"Microsoft.Blueprint/blueprints",
	}
	assert.Equal(t, expected, ARMEnumeratedTypes)
}
