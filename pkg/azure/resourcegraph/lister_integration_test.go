//go:build integration

package resourcegraph

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/require"
)

func TestResourceGraphListerListAll(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/list-all")
	fixture.Setup()

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)

	lister := NewResourceGraphLister(cred, nil)

	subscriptionID := fixture.Output("subscription_id")
	sub := azuretypes.SubscriptionInfo{
		ID: subscriptionID,
	}

	out := pipeline.New[model.AurelianModel]()
	go func() {
		defer out.Close()
		err := lister.ListAll(sub, out)
		require.NoError(t, err)
	}()

	results, err := out.Collect()
	require.NoError(t, err)
	testutil.AssertMinResults(t, results, 1)

	t.Run("discovers resource groups", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("resource_group_id"))
		testutil.AssertResultContainsString(t, results, fixture.Output("func_resource_group_id"))
	})

	t.Run("discovers virtual network", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("vnet_id"))
	})

	t.Run("discovers network security group", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("nsg_id"))
	})

	t.Run("discovers storage accounts", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("storage_account_id"))
		testutil.AssertResultContainsString(t, results, fixture.Output("func_storage_account_id"))
	})

	t.Run("discovers key vault", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("key_vault_id"))
	})

	t.Run("discovers virtual machine", func(t *testing.T) {
		testutil.AssertResultContainsString(t, results, fixture.Output("vm_id"))
	})
}
