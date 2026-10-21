package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/test/azuretest"
)

func TestCredentialAuthenticatesAgainstSelectedAuthority(t *testing.T) {
	// Synthetic credentials only; all HTTP is intercepted, never sent to Azure.
	t.Setenv("AZURE_TENANT_ID", "11111111-1111-1111-1111-111111111111")
	t.Setenv("AZURE_CLIENT_ID", "22222222-2222-2222-2222-222222222222")
	t.Setenv("AZURE_CLIENT_SECRET", "offline-test-secret")
	t.Setenv("AZURE_TOKEN_CREDENTIALS", "EnvironmentCredential")
	t.Setenv("AZURE_AUTHORITY_HOST", "https://attacker.invalid") // explicit module cloud wins
	for _, value := range []string{"", "public", "gcc-high"} {
		t.Run(value, func(t *testing.T) {
			e := azurecloud.Resolve(value)
			authority := strings.TrimSuffix(e.Cloud.ActiveDirectoryAuthorityHost, "/")
			tokenRequests := 0
			azuretest.Install(t, func(r *http.Request) (*http.Response, error) {
				assert.Equal(t, strings.TrimPrefix(authority, "https://"), r.URL.Host)
				if strings.Contains(r.URL.Path, ".well-known") {
					return azuretest.JSON(r, fmt.Sprintf(`{"authorization_endpoint":%q,"token_endpoint":%q,"issuer":%q}`, authority+"/tenant/oauth2/v2.0/authorize", authority+"/tenant/oauth2/v2.0/token", authority+"/tenant/v2.0")), nil
				}
				if r.Method != http.MethodPost {
					return nil, fmt.Errorf("unexpected offline request")
				}
				tokenRequests++
				require.NoError(t, r.ParseForm())
				assert.Equal(t, "offline-test-secret", r.Form.Get("client_secret"))
				assert.Contains(t, r.Form.Get("scope"), e.ARMScope())
				return azuretest.JSON(r, `{"access_token":"offline-token","expires_in":3600,"token_type":"Bearer"}`), nil
			})
			cred, err := NewAzureCredential(e)
			require.NoError(t, err)
			token, err := cred.GetToken(context.Background(), policy.TokenRequestOptions{Scopes: []string{e.ARMScope()}})
			require.NoError(t, err)
			assert.Equal(t, "offline-token", token.Token)
			assert.Equal(t, 1, tokenRequests)
		})
	}
}
