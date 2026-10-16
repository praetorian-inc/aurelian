package extraction

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/azure/auth"
	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/test/azuretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGovernmentAppConfigAcquiresServiceAudienceToken(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "11111111-1111-1111-1111-111111111111")
	t.Setenv("AZURE_CLIENT_ID", "22222222-2222-2222-2222-222222222222")
	t.Setenv("AZURE_CLIENT_SECRET", "offline-test-secret")
	t.Setenv("AZURE_TOKEN_CREDENTIALS", "EnvironmentCredential")
	tokenRequests := 0
	azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
		switch r.URL.Host {
		case "login.microsoftonline.us":
			if strings.Contains(r.URL.Path, ".well-known") {
				return azuretest.JSON(r, `{"authorization_endpoint":"https://login.microsoftonline.us/tenant/oauth2/v2.0/authorize","token_endpoint":"https://login.microsoftonline.us/tenant/oauth2/v2.0/token","issuer":"https://login.microsoftonline.us/tenant/v2.0"}`), nil
			}
			tokenRequests++
			require.NoError(t, r.ParseForm())
			if !slices.Contains(strings.Fields(r.Form.Get("scope")), "https://appconfig.azure.us/.default") {
				resp := azuretest.JSON(r, `{"error":"invalid_resource","error_description":"store endpoint is not the Government App Configuration audience"}`)
				resp.StatusCode = http.StatusBadRequest
				return resp, nil
			}
			return azuretest.JSON(r, `{"access_token":"offline-appconfig-token","expires_in":3600,"token_type":"Bearer"}`), nil
		case "store.azconfig.azure.us":
			assert.Equal(t, "Bearer offline-appconfig-token", r.Header.Get("Authorization"))
			resp := azuretest.JSON(r, `{"items":[{"key":"setting","value":"offline-value"}]}`)
			resp.Header.Set("Sync-Token", "offline=token;sn=1")
			return resp, nil
		default:
			return nil, fmt.Errorf("unexpected offline App Configuration destination: %s", r.URL.Host)
		}
	})
	cred, err := auth.NewAzureCredentialForCloud(azurecloud.Government)
	require.NoError(t, err)
	items, err := azuretest.Collect(func(out *pipeline.P[output.ScanInput]) error {
		return extractAppConfigKeyValues(extractContext{Context: context.Background(), Cred: cred}, output.AzureResource{ResourceID: "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.AppConfiguration/configurationStores/store"}, out)
	})
	require.NoError(t, err)
	assert.Len(t, items, 1)
	assert.Positive(t, tokenRequests)
}
