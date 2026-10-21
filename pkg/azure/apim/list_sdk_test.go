package apim

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/apimanagement/armapimanagement"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/test/azuretest"
)

func TestListAPIsSDKPagination(t *testing.T) {
	cred := &azuretest.Credential{}
	options := azurecloud.Resolve("").ARMClientOptions()
	calls := 0
	options.Transport = azuretest.TransportFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		assert.Equal(t, "management.azure.com", req.URL.Host)
		assert.Equal(t, APIListAPIVersion, req.URL.Query().Get("api-version"))
		assert.Equal(t, "Bearer offline-token", req.Header.Get("Authorization"))
		if calls == 1 {
			assert.Equal(t, "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.ApiManagement/service/service/apis", req.URL.Path)
			return azuretest.JSONResponse(req, http.StatusOK, `{"value":[{"name":"native","properties":{"type":"MCP","path":"mcp","protocols":["https"],"displayName":"Native"}}],"nextLink":"https://management.azure.com/next?api-version=2021-08-01&$skiptoken=token"}`), nil
		}
		assert.Equal(t, "/next", req.URL.Path)
		assert.Equal(t, "token", req.URL.Query().Get("$skiptoken"))
		return azuretest.JSONResponse(req, http.StatusOK, `{"value":[{"name":"rest","properties":{"subscriptionRequired":true}}]}`), nil
	})

	items, err := listAPIs(context.Background(), cred, "sub", "rg", "service", options)
	require.NoError(t, err)
	assert.Equal(t, 2, calls)
	assert.Equal(t, []APIInventoryItem{
		{APIID: "native", DisplayName: "Native", Path: "mcp", Protocols: []string{"https"}, IsMCPServer: true},
		{APIID: "rest", SubscriptionRequired: true},
	}, items)
	assert.Equal(t, []string{"https://management.core.windows.net//.default"}, cred.Scopes)
}

func TestListAPIsSDKRejectsForeignNextLink(t *testing.T) {
	for _, next := range []string{"https://foreign.example/next", "http://management.azure.com/next", "https://management.azure.com.evil/next"} {
		t.Run(next, func(t *testing.T) {
			options := azurecloud.Resolve("").ARMClientOptions()
			calls := 0
			options.Transport = azuretest.TransportFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				body, err := json.Marshal(map[string]any{"value": []any{}, "nextLink": next})
				require.NoError(t, err)
				return azuretest.JSONResponse(req, http.StatusOK, string(body)), nil
			})

			items, err := listAPIs(context.Background(), &azuretest.Credential{}, "sub", "rg", "service", options)
			require.Error(t, err)
			assert.Nil(t, items)
			assert.Equal(t, 1, calls)
		})
	}
}

func TestListAPIsSDKRetriesThrottling(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			options := azurecloud.Resolve("").ARMClientOptions()
			calls := 0
			options.Transport = azuretest.TransportFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					return azuretest.JSONResponse(req, status, `{"error":{"code":"throttled"}}`), nil
				}
				return azuretest.JSONResponse(req, http.StatusOK, `{"value":[]}`), nil
			})

			items, err := listAPIs(context.Background(), &azuretest.Credential{}, "sub", "rg", "service", options)
			require.NoError(t, err)
			assert.Empty(t, items)
			assert.Equal(t, 2, calls)
		})
	}
}

func TestListAPIsSDKError(t *testing.T) {
	options := azurecloud.Resolve("").ARMClientOptions()
	calls := 0
	options.Transport = azuretest.TransportFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return azuretest.JSONResponse(req, http.StatusForbidden, `{"error":{"code":"AuthorizationFailed","message":"denied"}}`), nil
	})

	items, err := listAPIs(context.Background(), &azuretest.Credential{}, "sub", "rg", "service", options)
	var responseError *azcore.ResponseError
	require.ErrorAs(t, err, &responseError)
	assert.Equal(t, http.StatusForbidden, responseError.StatusCode)
	assert.Nil(t, items)
	assert.Equal(t, 1, calls)
}

// Keep the existing page fixtures exercising the SDK decoder and production mapping.
func parseAPIListPage(body []byte) ([]APIInventoryItem, string, error) {
	var response armapimanagement.APICollection
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, "", err
	}
	return apiListResponseToItems(response), valueOf(response.NextLink), nil
}

func validateARMURL(raw string, base *url.URL) error {
	return azurecloud.ValidateARMURL(raw, base)
}
