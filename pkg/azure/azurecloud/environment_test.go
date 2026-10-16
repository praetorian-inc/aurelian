package azurecloud_test

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/test/azuretest"
)

func TestResolveDefaultsAndSDKMetadata(t *testing.T) {
	for _, value := range []string{"", "public", "gcc-high"} {
		e, err := azurecloud.Resolve(value)
		require.NoError(t, err)
		expected := cloud.AzurePublic
		expectedName := "public"
		if value == "gcc-high" {
			expected = cloud.AzureGovernment
			expectedName = "gcc-high"
		}
		assert.Equal(t, expectedName, e.Name)
		assert.Equal(t, expected.Services[cloud.ResourceManager].Endpoint, e.ARM)
		assert.Equal(t, strings.TrimRight(expected.Services[cloud.ResourceManager].Audience, "/")+"/.default", e.ARMScope)
		e.Cloud.Services[cloud.ResourceManager] = cloud.ServiceConfiguration{Endpoint: "mutated"}
		assert.NotEqual(t, "mutated", expected.Services[cloud.ResourceManager].Endpoint)
	}
	for _, invalid := range []string{"gcc", "GCCHigh", "GCC-High", "usgovernment", "USGovernment", "china", "usgovernmentdod", " public", "gcc-high ", "unknown"} {
		_, err := azurecloud.Resolve(invalid)
		require.ErrorContains(t, err, "unsupported Azure cloud type")
		assert.Contains(t, err.Error(), "choose public or gcc-high")
	}
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
		cred, recorder := azuretest.NewCredential(t, typ)
		client, err := armsubscriptions.NewClient(cred, azurecloud.ARMClientOptions(cred))
		if !assert.NoError(t, err) {
			return
		}
		_, err = client.NewListPager(nil).NextPage(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, []string{azurecloud.ForCredential(cred).ARMScope}, recorder.Scopes())
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
