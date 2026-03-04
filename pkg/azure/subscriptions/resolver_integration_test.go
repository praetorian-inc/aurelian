//go:build integration

package subscriptions

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSubscriptionResolverResolve(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/list-all")
	fixture.Setup()

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)

	resolver := NewSubscriptionResolver(cred)
	subscriptionID := fixture.Output("subscription_id")

	out := pipeline.New[azuretypes.SubscriptionInfo]()
	go func() {
		defer out.Close()
		err := resolver.Resolve(subscriptionID, out)
		require.NoError(t, err)
	}()

	results, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, results, 1)

	sub := results[0]
	assert.Equal(t, subscriptionID, sub.ID)
	assert.NotEmpty(t, sub.DisplayName)
	assert.NotEmpty(t, sub.TenantID)
}
