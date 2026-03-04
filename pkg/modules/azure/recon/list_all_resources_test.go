package recon

import (
	"context"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	azuretypes "github.com/praetorian-inc/aurelian/pkg/azure/types"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAzureListAllModule_Registration(t *testing.T) {
	mod, ok := plugin.Get(plugin.PlatformAzure, plugin.CategoryRecon, "list-all")
	require.True(t, ok, "module should be registered")
	assert.Equal(t, "list-all", mod.ID())
	assert.Equal(t, plugin.PlatformAzure, mod.Platform())
	assert.Equal(t, plugin.CategoryRecon, mod.Category())
	assert.Equal(t, "stealth", mod.OpsecLevel())
}

func TestAzureListAllModule_Parameters(t *testing.T) {
	mod, ok := plugin.Get(plugin.PlatformAzure, plugin.CategoryRecon, "list-all")
	require.True(t, ok)

	params := mod.Parameters()
	require.NotNil(t, params)

	p, err := plugin.ParametersFrom(params)
	require.NoError(t, err)

	names := make(map[string]bool)
	for _, param := range p {
		names[param.Name] = true
	}
	assert.True(t, names["subscription-id"], "should have subscription-id parameter")
}

func TestAzureListAllModule_Run_ExplicitIDsPipesResolverToLister(t *testing.T) {
	restore := stubConstructorsForRunTests()
	defer restore()

	resolved := []string{}
	listed := []string{}

	newResolver = func(azcore.TokenCredential) subscriptionResolver {
		return &fakeResolver{
			resolveFn: func(id string, out *pipeline.P[azuretypes.SubscriptionInfo]) error {
				resolved = append(resolved, id)
				out.Send(azuretypes.SubscriptionInfo{ID: id, DisplayName: "sub-" + id, TenantID: "tenant"})
				return nil
			},
		}
	}
	newLister = func(azcore.TokenCredential) resourceLister {
		return &fakeLister{
			listAllFn: func(sub azuretypes.SubscriptionInfo, _ *pipeline.P[model.AurelianModel]) error {
				listed = append(listed, sub.ID)
				return nil
			},
		}
	}

	m := &AzureListAllResourcesModule{ListAllConfig: ListAllConfig{AzureCommonRecon: plugin.AzureCommonRecon{SubscriptionID: []string{"sub-1", "sub-2"}}}}
	out := pipeline.New[model.AurelianModel]()

	err := m.Run(plugin.Config{}, out)
	require.NoError(t, err)
	assert.Equal(t, []string{"sub-1", "sub-2"}, resolved)
	assert.Equal(t, []string{"sub-1", "sub-2"}, listed)
}

func TestAzureListAllModule_Run_AllWithNoSubscriptions_ReturnsNil(t *testing.T) {
	restore := stubConstructorsForRunTests()
	defer restore()

	newResolver = func(azcore.TokenCredential) subscriptionResolver {
		return &fakeResolver{
			listAllFn: func() ([]azuretypes.SubscriptionInfo, error) {
				return []azuretypes.SubscriptionInfo{}, nil
			},
		}
	}

	m := &AzureListAllResourcesModule{ListAllConfig: ListAllConfig{AzureCommonRecon: plugin.AzureCommonRecon{SubscriptionID: []string{"all"}}}}
	out := pipeline.New[model.AurelianModel]()

	err := m.Run(plugin.Config{}, out)
	require.NoError(t, err)
}

func TestAzureListAllModule_Run_ResolverError_FailsFast(t *testing.T) {
	restore := stubConstructorsForRunTests()
	defer restore()

	expectedErr := errors.New("resolver failed")
	newResolver = func(azcore.TokenCredential) subscriptionResolver {
		return &fakeResolver{
			resolveFn: func(string, *pipeline.P[azuretypes.SubscriptionInfo]) error {
				return expectedErr
			},
		}
	}

	m := &AzureListAllResourcesModule{ListAllConfig: ListAllConfig{AzureCommonRecon: plugin.AzureCommonRecon{SubscriptionID: []string{"sub-1"}}}}
	out := pipeline.New[model.AurelianModel]()

	err := m.Run(plugin.Config{}, out)
	require.Error(t, err)
	assert.ErrorIs(t, err, expectedErr)
}

type fakeResolver struct {
	resolveFn func(id string, out *pipeline.P[azuretypes.SubscriptionInfo]) error
	listAllFn func() ([]azuretypes.SubscriptionInfo, error)
}

func (f *fakeResolver) Resolve(id string, out *pipeline.P[azuretypes.SubscriptionInfo]) error {
	if f.resolveFn == nil {
		return nil
	}

	return f.resolveFn(id, out)
}

func (f *fakeResolver) ListAllSubscriptions() ([]azuretypes.SubscriptionInfo, error) {
	if f.listAllFn == nil {
		return nil, nil
	}

	return f.listAllFn()
}

type fakeLister struct {
	listAllFn func(sub azuretypes.SubscriptionInfo, out *pipeline.P[model.AurelianModel]) error
}

func (f *fakeLister) ListAll(sub azuretypes.SubscriptionInfo, out *pipeline.P[model.AurelianModel]) error {
	if f.listAllFn == nil {
		return nil
	}

	return f.listAllFn(sub, out)
}

func stubConstructorsForRunTests() func() {
	originalNewCredential := newCredential
	originalNewResolver := newResolver
	originalNewLister := newLister

	newCredential = func() (azcore.TokenCredential, error) {
		return &fakeCredential{}, nil
	}
	newResolver = func(azcore.TokenCredential) subscriptionResolver {
		return &fakeResolver{}
	}
	newLister = func(azcore.TokenCredential) resourceLister {
		return &fakeLister{}
	}

	return func() {
		newCredential = originalNewCredential
		newResolver = originalNewResolver
		newLister = originalNewLister
	}
}

type fakeCredential struct{}

func (f *fakeCredential) GetToken(_ context.Context, _ policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, nil
}
