package azurecloud_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/test/azuretest"
)

func TestResolveDefaultsToPublic(t *testing.T) {
	for _, value := range []string{"", "public", "unknown", " PUBLIC ", "GCC-HIGH", " gcc-high ", "usgovernment", "AzureUSGovernment", "gcc"} {
		t.Run(value, func(t *testing.T) {
			env := azurecloud.Resolve(value)
			assert.Equal(t, "public", env.Name)
			assert.Equal(t, cloud.AzurePublic, env.Cloud)
			assert.Equal(t, env.Cloud, env.ARMClientOptions().Cloud)
			assert.Equal(t, env.Cloud, env.ClientOptions().Cloud)
		})
	}
}

func TestARMClientUsesEnvironmentEndpointAndAudience(t *testing.T) {
	for _, tc := range []struct {
		name     string
		env      azurecloud.Environment
		host     string
		audience string
	}{
		{"public", azurecloud.Resolve(""), "management.azure.com", "https://management.core.windows.net/"},
		{"government", azurecloud.Resolve("gcc-high"), "management.usgovcloudapi.net", "https://management.core.usgovcloudapi.net/"},
		{"zero defaults to public", azurecloud.Environment{}, "management.azure.com", "https://management.core.windows.net/"},
		{"custom", azurecloud.Environment{Cloud: cloud.Configuration{Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
			cloud.ResourceManager: {Endpoint: "https://arm.example.test", Audience: "https://arm.example.test"},
		}}}, "arm.example.test", "https://arm.example.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cred := &azuretest.Credential{}
			opts := tc.env.ARMClientOptions()
			opts.Transport = azuretest.TransportFunc(func(req *http.Request) (*http.Response, error) {
				assert.Equal(t, tc.host, req.URL.Host)
				assert.Equal(t, "Bearer offline-token", req.Header.Get("Authorization"))
				return azuretest.JSONResponse(req, http.StatusOK, `{"subscriptionId":"sub"}`), nil
			})

			client, err := armsubscriptions.NewClient(cred, opts)
			require.NoError(t, err)
			resp, err := client.Get(context.Background(), "sub", nil)
			require.NoError(t, err)
			assert.Equal(t, "sub", *resp.SubscriptionID)
			assert.Equal(t, []string{tc.audience + "/.default"}, cred.Scopes)
		})
	}
}
