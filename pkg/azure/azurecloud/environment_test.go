package azurecloud_test

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/test/azuretest"
)

func TestResolveDefaultsAndSDKMetadata(t *testing.T) {
	for _, value := range []string{"", "public", "gcc-high"} {
		e := azurecloud.Resolve(value)
		expected := cloud.AzurePublic
		expectedName := "public"
		expectedScope := "https://management.core.windows.net//.default"
		expectedAppConfigAudience := ""
		if value == "gcc-high" {
			expected = cloud.AzureGovernment
			expectedName = "gcc-high"
			expectedScope = "https://management.core.usgovcloudapi.net//.default"
			expectedAppConfigAudience = "https://appconfig.azure.us"
		}
		assert.Equal(t, expectedName, e.Name)
		assert.Equal(t, expected.Services[cloud.ResourceManager].Endpoint, e.ARMEndpoint())
		// Matches what azcore/arm/runtime requests, trailing-slash audience included.
		assert.Equal(t, expectedScope, e.ARMScope())
		assert.Equal(t, expectedAppConfigAudience, e.AppConfigAudience)
	}
	// Only the exact Government selector leaves Public.
	for _, other := range []string{"gcc", "GCCHigh", "GCC-High", "usgovernment", "USGovernment", "china", "usgovernmentdod", " public", "gcc-high ", "unknown"} {
		assert.Equal(t, azurecloud.Public, azurecloud.Resolve(other).Name, other)
	}
}

func TestSupports(t *testing.T) {
	public := azurecloud.Resolve(azurecloud.Public)
	gov := azurecloud.Resolve(azurecloud.Government)
	assert.True(t, public.Supports(nil))
	assert.True(t, gov.Supports(nil))
	assert.True(t, public.Supports([]string{azurecloud.Public}))
	assert.False(t, gov.Supports([]string{azurecloud.Public}))
}

func TestCloudIsolationBothOrdersAndConcurrent(t *testing.T) {
	azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
		typ := "public"
		if r.URL.Host == "management.usgovcloudapi.net" {
			typ = "gcc-high"
		} else {
			assert.Equal(t, "management.azure.com", r.URL.Host)
		}
		assert.Equal(t, "Bearer offline-"+typ, r.Header.Get("Authorization"))
		return azuretest.JSON(r, `{"value":[]}`), nil
	})
	run := func(typ string) {
		cred, env := azuretest.NewCredential(t, typ)
		client, err := armsubscriptions.NewClient(cred, azurecloud.ARMClientOptions(env))
		if !assert.NoError(t, err) {
			return
		}
		_, err = client.NewListPager(nil).NextPage(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, []string{env.ARMScope()}, cred.Scopes())
	}
	for _, order := range [][]string{{"public", "gcc-high"}, {"gcc-high", "public"}} {
		for _, typ := range order {
			run(typ)
		}
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		for _, typ := range []string{"public", "gcc-high"} {
			wg.Add(1)
			go func() { defer wg.Done(); run(typ) }()
		}
	}
	wg.Wait()
}
