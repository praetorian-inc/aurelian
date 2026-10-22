package azurecloud_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/data/azappconfig"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/test/azuretest"
)

func TestResolveGovernment(t *testing.T) {
	env := azurecloud.Resolve("gcc-high")
	assert.Equal(t, azurecloud.Government, env.Name)
	assert.Equal(t, cloud.AzureGovernment, env.Cloud)
	assert.Equal(t, "https://appconfig.azure.us", env.AppConfigAudience)
	assert.Equal(t, ".blob.core.usgovcloudapi.net", env.BlobSuffix)
	assert.Equal(t, ".azurewebsites.us", env.AppServiceSuffix)
	assert.Equal(t, ".usgovtrafficmanager.net", env.TrafficManagerSuffix)
	assert.Equal(t, env.Cloud, env.ARMClientOptions().Cloud)
	assert.Equal(t, env.Cloud, env.ClientOptions().Cloud)
}

func TestSupports(t *testing.T) {
	for _, name := range []string{azurecloud.Public, azurecloud.Government} {
		env := azurecloud.Resolve(name)
		assert.True(t, env.Supports(nil))
		assert.True(t, env.Supports([]string{}))
		assert.True(t, env.Supports([]string{azurecloud.Public, azurecloud.Government}))
		assert.True(t, env.Supports([]string{name}))
		assert.False(t, env.Supports([]string{"unsupported"}))
		assert.Equal(t, name == azurecloud.Public, env.Supports([]string{azurecloud.Public}))
		assert.Equal(t, name == azurecloud.Government, env.Supports([]string{azurecloud.Government}))
	}
}

// Exercise the real SDK credential chain and clients without sending any HTTP to Azure.
func TestSDKRequestsStayInSelectedCloud(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "11111111-1111-1111-1111-111111111111")
	t.Setenv("AZURE_CLIENT_ID", "22222222-2222-2222-2222-222222222222")
	t.Setenv("AZURE_CLIENT_SECRET", "offline-secret")
	t.Setenv("AZURE_TOKEN_CREDENTIALS", "EnvironmentCredential")
	t.Setenv("AZURE_AUTHORITY_HOST", "https://wrong-authority.invalid")

	for _, tc := range []struct {
		cloud, authority, armHost, armScope, store, appScope string
	}{
		{"public", "login.microsoftonline.com", "management.azure.com", "https://management.core.windows.net//.default", "store.azconfig.io", "https://store.azconfig.io/.default"},
		{"gcc-high", "login.microsoftonline.us", "management.usgovcloudapi.net", "https://management.core.usgovcloudapi.net//.default", "store.azconfig.azure.us", "https://appconfig.azure.us/.default"},
		{"legacy", "login.microsoftonline.com", "management.azure.com", "https://management.core.windows.net//.default", "store.azconfig.io", "https://store.azconfig.io/.default"},
	} {
		t.Run(tc.cloud, func(t *testing.T) {
			var scopes []string
			var destinations []string
			transport := azuretest.TransportFunc(func(req *http.Request) (*http.Response, error) {
				require.Equal(t, "https", req.URL.Scheme)
				destinations = append(destinations, req.URL.Host)
				switch req.URL.Host {
				case tc.authority:
					return respondToAuthority(t, req, tc.authority, &scopes), nil
				case tc.armHost:
					assert.Equal(t, "Bearer offline-token", req.Header.Get("Authorization"))
					assert.Equal(t, "/subscriptions/sub", req.URL.Path)
					return azuretest.JSONResponse(req, http.StatusOK, `{"subscriptionId":"sub"}`), nil
				case tc.store:
					assert.Equal(t, "Bearer offline-token", req.Header.Get("Authorization"))
					assert.Equal(t, "/kv", req.URL.Path)
					response := azuretest.JSONResponse(req, http.StatusOK, `{"items":[{"key":"setting","value":"offline-value"}]}`)
					response.Header.Set("Sync-Token", "offline=token;sn=1")
					return response, nil
				default:
					assert.Fail(t, "unexpected HTTP destination", "%s", req.URL)
					return nil, fmt.Errorf("unexpected destination: %s", req.URL)
				}
			})
			env := azurecloud.Resolve(tc.cloud)
			options := env.ClientOptions()
			options.Transport = transport
			cred, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{ClientOptions: options})
			require.NoError(t, err)

			armOptions := env.ARMClientOptions()
			armOptions.Transport = transport
			armClient, err := armsubscriptions.NewClient(cred, armOptions)
			require.NoError(t, err)
			_, err = armClient.Get(context.Background(), "sub", nil)
			require.NoError(t, err)

			appClient, err := azappconfig.NewClient("https://"+tc.store, env.AppConfigCredential(cred), &azappconfig.ClientOptions{ClientOptions: options})
			require.NoError(t, err)
			page, err := appClient.NewListSettingsPager(azappconfig.SettingSelector{}, nil).NextPage(context.Background())
			require.NoError(t, err)
			require.Len(t, page.Settings, 1)
			assert.Equal(t, "offline-value", *page.Settings[0].Value)
			assert.ElementsMatch(t, []string{tc.armScope, tc.appScope}, scopes)
			assert.Contains(t, destinations, tc.authority)
			assert.Contains(t, destinations, tc.armHost)
			assert.Contains(t, destinations, tc.store)
		})
	}
}

func TestAppConfigPublicCredentialIsUnchanged(t *testing.T) {
	cred := &azuretest.Credential{}
	assert.Same(t, cred, azurecloud.Resolve("").AppConfigCredential(cred))
}

func respondToAuthority(t *testing.T, req *http.Request, authority string, scopes *[]string) *http.Response {
	t.Helper()
	base := "https://" + authority + "/tenant"
	if req.URL.Path == "/common/discovery/instance" {
		return azuretest.JSONResponse(req, http.StatusOK, fmt.Sprintf(
			`{"tenant_discovery_endpoint":%q,"metadata":[{"preferred_network":%q,"preferred_cache":%q,"aliases":[%q]}]}`,
			base+"/v2.0/.well-known/openid-configuration", authority, authority, authority))
	}
	if strings.Contains(req.URL.Path, ".well-known") {
		return azuretest.JSONResponse(req, http.StatusOK, fmt.Sprintf(
			`{"authorization_endpoint":%q,"token_endpoint":%q,"issuer":%q}`,
			base+"/oauth2/v2.0/authorize", base+"/oauth2/v2.0/token", base+"/v2.0"))
	}
	require.Equal(t, http.MethodPost, req.Method)
	require.NoError(t, req.ParseForm())
	assert.Equal(t, "offline-secret", req.Form.Get("client_secret"))
	// MSAL also adds OIDC scopes; record only service audiences.
	for _, scope := range strings.Fields(req.Form.Get("scope")) {
		if strings.HasSuffix(scope, "/.default") {
			*scopes = append(*scopes, scope)
		}
	}
	return azuretest.JSONResponse(req, http.StatusOK, `{"access_token":"offline-token","expires_in":3600,"token_type":"Bearer"}`)
}
