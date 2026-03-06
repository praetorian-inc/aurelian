//go:build integration

package resourcegraph

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
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

	input := ListerInput{Subscription: sub}

	out := pipeline.New[output.AzureResource]()
	go func() {
		defer out.Close()
		err := lister.List(input, out)
		require.NoError(t, err)
	}()

	results, err := out.Collect()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(results), 1, "expected at least 1 resource")

	resourceIDs := make(map[string]bool, len(results))
	for _, r := range results {
		resourceIDs[r.ResourceID] = true
	}

	t.Run("discovers virtual network", func(t *testing.T) {
		assert.True(t, resourceIDs[fixture.Output("vnet_id")])
	})

	t.Run("discovers network security group", func(t *testing.T) {
		assert.True(t, resourceIDs[fixture.Output("nsg_id")])
	})

	t.Run("discovers storage accounts", func(t *testing.T) {
		assert.True(t, resourceIDs[fixture.Output("storage_account_id")])
		assert.True(t, resourceIDs[fixture.Output("func_storage_account_id")])
	})

	t.Run("discovers key vault", func(t *testing.T) {
		assert.True(t, resourceIDs[fixture.Output("key_vault_id")])
	})

	t.Run("discovers virtual machine", func(t *testing.T) {
		assert.True(t, resourceIDs[fixture.Output("vm_id")])
	})
}

func TestResourceGraphListerListByTypes(t *testing.T) {
	fixture := testutil.NewAzureFixture(t, "azure/recon/list-all")
	fixture.Setup()

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)

	lister := NewResourceGraphLister(cred, nil)

	subscriptionID := fixture.Output("subscription_id")
	sub := azuretypes.SubscriptionInfo{
		ID: subscriptionID,
	}

	resourceTypes := []string{
		"microsoft.compute/virtualmachines",
		"microsoft.storage/storageaccounts",
		"microsoft.network/virtualnetworks",
		"microsoft.keyvault/vaults",
		"microsoft.network/networksecuritygroups",
	}

	input := ListerInput{Subscription: sub, ResourceTypes: resourceTypes}

	out := pipeline.New[output.AzureResource]()
	go func() {
		defer out.Close()
		err := lister.List(input, out)
		require.NoError(t, err)
	}()

	results, err := out.Collect()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(results), 5, "expected at least 5 resources for the requested types")

	// Build a set of all returned resource IDs for assertion.
	resourceIDs := make(map[string]bool, len(results))
	resourceTypesFound := make(map[string]bool, len(results))
	for _, r := range results {
		resourceIDs[r.ResourceID] = true
		resourceTypesFound[r.ResourceType] = true
	}

	t.Run("returns only requested resource types", func(t *testing.T) {
		allowed := map[string]bool{
			"microsoft.compute/virtualmachines":       true,
			"microsoft.storage/storageaccounts":       true,
			"microsoft.network/virtualnetworks":       true,
			"microsoft.keyvault/vaults":               true,
			"microsoft.network/networksecuritygroups": true,
		}
		for _, r := range results {
			assert.True(t, allowed[r.ResourceType],
				"unexpected resource type %q in results", r.ResourceType)
		}
	})

	t.Run("discovers virtual machine", func(t *testing.T) {
		assert.True(t, resourceIDs[fixture.Output("vm_id")],
			"expected VM %s in results", fixture.Output("vm_id"))
	})

	t.Run("discovers storage accounts", func(t *testing.T) {
		assert.True(t, resourceIDs[fixture.Output("storage_account_id")],
			"expected storage account in results")
		assert.True(t, resourceIDs[fixture.Output("func_storage_account_id")],
			"expected function storage account in results")
	})

	t.Run("discovers virtual network", func(t *testing.T) {
		assert.True(t, resourceIDs[fixture.Output("vnet_id")],
			"expected vnet in results")
	})

	t.Run("discovers key vault", func(t *testing.T) {
		assert.True(t, resourceIDs[fixture.Output("key_vault_id")],
			"expected key vault in results")
	})

	t.Run("discovers network security group", func(t *testing.T) {
		assert.True(t, resourceIDs[fixture.Output("nsg_id")],
			"expected NSG in results")
	})

	t.Run("populates resource fields", func(t *testing.T) {
		for _, r := range results {
			assert.NotEmpty(t, r.ResourceID, "ResourceID should be populated")
			assert.NotEmpty(t, r.ResourceType, "ResourceType should be populated")
			assert.NotEmpty(t, r.SubscriptionID, "SubscriptionIDs should be populated")
			assert.NotEmpty(t, r.DisplayName, "DisplayName should be populated")
			assert.NotEmpty(t, r.Location, "Location should be populated")
			assert.NotEmpty(t, r.ResourceGroup, "ResourceGroup should be populated")
		}
	})

	t.Run("excludes unrequested resource types", func(t *testing.T) {
		assert.False(t, resourceTypesFound["microsoft.web/sites"],
			"web apps should not appear when not requested")
		assert.False(t, resourceTypesFound["microsoft.resources/resourcegroups"],
			"resource groups should not appear when not requested")
	})
}
