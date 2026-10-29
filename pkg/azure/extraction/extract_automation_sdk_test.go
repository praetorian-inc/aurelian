package extraction

import (
	"context"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/automation/armautomation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/test/azuretest"
)

func TestFetchRunbookContentSDK(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"script", http.StatusOK, "Write-Output 'example'\r\n\x00\xff"},
		{"empty", http.StatusOK, ""},
		{"forbidden", http.StatusForbidden, `{"error":{"code":"AuthorizationFailed"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cred := &azuretest.Credential{}
			options := azurecloud.Resolve("").ARMClientOptions()
			options.APIVersion = "2023-11-01"
			options.Transport = azuretest.TransportFunc(func(req *http.Request) (*http.Response, error) {
				assert.Equal(t, http.MethodGet, req.Method)
				assert.Equal(t, "management.azure.com", req.URL.Host)
				assert.Equal(t, "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Automation/automationAccounts/account/runbooks/runbook/content", req.URL.Path)
				assert.Equal(t, "2023-11-01", req.URL.Query().Get("api-version"))
				assert.Equal(t, "text/plain", req.Header.Get("Accept"))
				response := azuretest.JSONResponse(req, tc.status, tc.body)
				response.Header.Set("Content-Type", "text/plain")
				return response, nil
			})
			client, err := armautomation.NewRunbookClient("sub", cred, options)
			require.NoError(t, err)

			content, err := fetchRunbookContent(context.Background(), client, "rg", "account", "runbook")
			if tc.status != http.StatusOK {
				var responseError *azcore.ResponseError
				require.ErrorAs(t, err, &responseError)
				assert.Equal(t, tc.status, responseError.StatusCode)
				assert.Nil(t, content)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, []byte(tc.body), content)
		})
	}
}
