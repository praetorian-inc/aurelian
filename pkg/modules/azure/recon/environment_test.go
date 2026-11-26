package recon

import (
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/aurelian/pkg/azure/armenum"
	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/pkg/azure/dnstakeover"
	"github.com/praetorian-inc/aurelian/pkg/azure/extraction"
	"github.com/praetorian-inc/aurelian/pkg/azure/resourcegraph"
	"github.com/praetorian-inc/aurelian/pkg/azure/subscriptions"
	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/templates"
	"github.com/praetorian-inc/aurelian/test/azuretest"
)

func TestAzureConsumersUseSuppliedEnvironment(t *testing.T) {
	env := azurecloud.Environment{
		Name: "test",
		Cloud: cloud.Configuration{Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
			cloud.ResourceManager: {Endpoint: "https://arm.example.test", Audience: "https://arm.example.test"},
		}},
	}
	sub := azuretypes.SubscriptionInfo{ID: "00000000-0000-0000-0000-000000000001"}
	resource := output.AzureResource{
		ResourceID:     "/subscriptions/" + sub.ID + "/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm",
		SubscriptionID: sub.ID,
		ResourceType:   "Microsoft.Compute/virtualMachines",
	}

	for _, tc := range []struct {
		name string
		run  func(*testing.T, azcore.TokenCredential)
	}{
		{"subscription resolution", func(t *testing.T, cred azcore.TokenCredential) {
			err := subscriptions.NewSubscriptionResolver(cred, env).Resolve(sub.ID, nil)
			require.Error(t, err)
		}},
		{"subscription listing", func(t *testing.T, cred azcore.TokenCredential) {
			_, err := subscriptions.NewSubscriptionResolver(cred, env).ListAllSubscriptions()
			require.Error(t, err)
		}},
		{"resource graph listing", func(t *testing.T, cred azcore.TokenCredential) {
			err := resourcegraph.NewResourceGraphLister(cred, env, nil).List(resourcegraph.ListerInput{Subscription: sub}, nil)
			require.Error(t, err)
		}},
		{"resource graph query", func(t *testing.T, cred azcore.TokenCredential) {
			err := resourcegraph.NewResourceGraphLister(cred, env, nil).Query(resourcegraph.QueryInput{
				Sub: sub, Template: &templates.ARGQueryTemplate{ID: "test", Query: "Resources"},
			}, nil)
			require.Error(t, err)
		}},
		{"ARM enumeration", func(t *testing.T, cred azcore.TokenCredential) {
			err := armenum.NewARMEnumerator(cred, env).List(sub, nil)
			require.Error(t, err)
		}},
		{"DNS enumeration", func(t *testing.T, cred azcore.TokenCredential) {
			require.NoError(t, dnstakeover.NewDNSEnumerator(cred, env).EnumerateSubscription(sub.ID, nil))
		}},
		{"extraction dispatch", func(t *testing.T, cred azcore.TokenCredential) {
			require.NoError(t, extraction.NewAzureExtractor(cred, env).Extract(resource, nil))
		}},
		{"resource ID hydration", func(t *testing.T, cred azcore.TokenCredential) {
			module := &AzureFindSecretsModule{}
			listed, err := module.listByResourceID(AzureFindSecretsConfig{
				AzureCommonRecon: plugin.AzureCommonRecon{AzureCredential: cred, Env: env},
				ResourceID:       []string{resource.ResourceID},
			})
			require.NoError(t, err)
			items, err := listed.Collect()
			require.NoError(t, err)
			require.Len(t, items, 1)
		}},
		{"subscription scan setup", func(t *testing.T, cred azcore.TokenCredential) {
			module := &AzureFindSecretsModule{}
			_, err := module.listBySubscription(AzureFindSecretsConfig{
				AzureCommonRecon: plugin.AzureCommonRecon{AzureCredential: cred, Env: env, SubscriptionIDs: []string{"all"}},
			})
			require.Error(t, err)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Stop at authentication so these tests cannot make HTTP requests.
			cred := &azuretest.Credential{Err: errors.New("offline credential")}
			tc.run(t, cred)
			require.NotEmpty(t, cred.Scopes)
			for _, scope := range cred.Scopes {
				assert.Equal(t, "https://arm.example.test/.default", scope)
			}
		})
	}
}
