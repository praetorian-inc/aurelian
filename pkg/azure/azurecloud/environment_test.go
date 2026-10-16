package azurecloud_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestExactOriginAndBlobBoundaries(t *testing.T) {
	e, _ := azurecloud.Resolve("gcc-high")
	for _, raw := range []string{"https://management.azure.com/x", "http://management.usgovcloudapi.net/x", "https://management.usgovcloudapi.net.attacker/x", "https://evil@management.usgovcloudapi.net/x", "https://management.usgovcloudapi.net:444/x", "https://management.usgovcloudapi.net/x#fragment", "//management.usgovcloudapi.net/x"} {
		require.Error(t, azurecloud.ValidateURL(raw, e.ARM), raw)
	}
	require.NoError(t, azurecloud.ValidateURL(e.ARM+"/subscriptions?next=opaque", e.ARM))
	require.NoError(t, azurecloud.ValidateBlobURL("https://managed.blob.core.usgovcloudapi.net/log?sig=fake", e))
	require.NoError(t, azurecloud.ValidateBlobURL("https://managed.blob.core.usgovcloudapi.net:443/log?sig=fake", e))
	for _, raw := range []string{"https://managed.blob.core.windows.net/log", "https://a.b.blob.core.usgovcloudapi.net/log", "https://a.blob.core.usgovcloudapi.net.attacker/log", "https://a.blob.core.usgovcloudapi.net:444/log", "http://a.blob.core.usgovcloudapi.net/log"} {
		require.Error(t, azurecloud.ValidateBlobURL(raw, e), raw)
	}
	for _, name := range []string{"", "a.b", "a/b", "a?x", "a@evil"} {
		_, err := azurecloud.Endpoint(name, e.BlobSuffix)
		require.Error(t, err)
	}
}

func TestARMClientsRejectCrossCloudPaginationAndRedirects(t *testing.T) {
	for _, cloudType := range []string{"public", "gcc-high"} {
		for _, attack := range []string{"pagination", "redirect", "subdomain-redirect"} {
			t.Run(cloudType+"/"+attack, func(t *testing.T) {
				cred, recorder := azuretest.NewCredential(t, cloudType)
				e := azurecloud.ForCredential(cred)
				calls := 0
				azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
					calls++
					require.Equal(t, strings.TrimPrefix(e.ARM, "https://"), r.URL.Host)
					require.Equal(t, "Bearer offline-"+cloudType, r.Header.Get("Authorization"))
					target := "https://management.azure.com/subscriptions"
					if cloudType == "public" {
						target = "https://management.usgovcloudapi.net/subscriptions"
					}
					if attack == "subdomain-redirect" {
						target = e.ARM[:8] + "child." + e.ARM[8:] + "/subscriptions"
					}
					resp := azuretest.JSON(r, fmt.Sprintf(`{"value":[],"nextLink":%q}`, target))
					if attack != "pagination" {
						resp.StatusCode = http.StatusTemporaryRedirect
						resp.Header.Set("Location", target)
					}
					return resp, nil
				})
				client, err := armsubscriptions.NewClient(cred, azurecloud.ARMClientOptions(cred))
				require.NoError(t, err)
				pager := client.NewListPager(nil)
				_, err = pager.NextPage(context.Background())
				if attack == "pagination" {
					require.NoError(t, err)
					_, err = pager.NextPage(context.Background())
				}
				require.Error(t, err)
				assert.Equal(t, 1, calls, "must not contact redirect or nextLink destination")
				assert.Contains(t, recorder.Scopes(), e.ARMScope)
			})
		}
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

func TestRawHTTPClientNeverFollowsRedirects(t *testing.T) {
	calls := 0
	azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
		calls++
		resp := azuretest.JSON(r, "")
		resp.StatusCode = http.StatusFound
		resp.Header.Set("Location", "https://child.management.usgovcloudapi.net/exfil")
		return resp, nil
	})
	req, _ := http.NewRequest(http.MethodGet, "https://management.usgovcloudapi.net/x", nil)
	req.Header.Set("Authorization", "Bearer fake")
	resp, err := azurecloud.HTTPClient(time.Second).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	assert.Equal(t, 1, calls)
}
