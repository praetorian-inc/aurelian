package armenum

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/test/azuretest"
)

func TestPolicySDKPagerPreservesMalformedMetadataTolerance(t *testing.T) {
	options := azurecloud.Resolve("").ARMClientOptions()
	cred := &azuretest.Credential{}
	calls := 0
	options.Transport = azuretest.TransportFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		assert.Equal(t, "management.azure.com", req.URL.Host)
		assert.Equal(t, "Bearer offline-token", req.Header.Get("Authorization"))
		if calls == 1 {
			assert.Equal(t, "2023-04-01", req.URL.Query().Get("api-version"))
			return azuretest.JSONResponse(req, http.StatusOK, `{"value":[
				{"id":"one","name":"one","properties":{"policyType":"Custom","displayName":"First","parameters":{"p":{"metadata":{"assignPermissions":"true","strongType":123}}}}},
				"malformed definition",
				{"id":123},
				{"id":"builtin","properties":{"policyType":"BuiltIn"}}
			],"nextLink":"https://management.azure.com/next"}`), nil
		}
		assert.Equal(t, "/next", req.URL.Path)
		return azuretest.JSONResponse(req, http.StatusOK, `{"value":[{"id":"two"}]}`), nil
	})

	pager, err := newPolicyDefinitionsPager("sub", cred, options)
	require.NoError(t, err)
	page, err := pager.NextPage(context.Background())
	require.NoError(t, err)
	require.Len(t, page.Value, 2)
	assert.Equal(t, to.Ptr("one"), page.Value[0].ID)
	assert.Equal(t, to.Ptr("First"), page.Value[0].Properties.DisplayName)
	assert.Equal(t, "Custom", string(*page.Value[0].Properties.PolicyType))
	assert.Equal(t, "BuiltIn", string(*page.Value[1].Properties.PolicyType))
	require.True(t, pager.More())

	page, err = pager.NextPage(context.Background())
	require.NoError(t, err)
	require.Len(t, page.Value, 1)
	assert.Equal(t, to.Ptr("two"), page.Value[0].ID)
	assert.False(t, pager.More())
	assert.Equal(t, 2, calls)
	assert.Equal(t, []string{"https://management.core.windows.net//.default"}, cred.Scopes)
}

func TestPolicySDKPagerRejectsForeignNextLink(t *testing.T) {
	options := azurecloud.Resolve("").ARMClientOptions()
	calls := 0
	options.Transport = azuretest.TransportFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return azuretest.JSONResponse(req, http.StatusOK, `{"value":[],"nextLink":"https://foreign.example/next"}`), nil
	})

	pager, err := newPolicyDefinitionsPager("sub", &azuretest.Credential{}, options)
	require.NoError(t, err)
	_, err = pager.NextPage(context.Background())
	require.Error(t, err)
	assert.Equal(t, 1, calls)
}

func TestPolicySDKPagerRetriesServiceUnavailable(t *testing.T) {
	options := azurecloud.Resolve("").ARMClientOptions()
	calls := 0
	options.Transport = azuretest.TransportFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return azuretest.JSONResponse(req, http.StatusServiceUnavailable, `{"error":{"code":"ServiceUnavailable"}}`), nil
		}
		return azuretest.JSONResponse(req, http.StatusOK, `{"value":[{"id":"custom"}]}`), nil
	})
	pager, err := newPolicyDefinitionsPager("sub", &azuretest.Credential{}, options)
	require.NoError(t, err)

	paginator := newPaginator()
	retries := 0
	paginator.Backoff = func(attempt int) {
		assert.Equal(t, 0, attempt)
		retries++
	}
	var ids []string
	err = paginator.Paginate(func() (bool, error) {
		page, err := pager.NextPage(context.Background())
		if err != nil {
			return false, handleListError(err, "policyDefinitions", "sub")
		}
		for _, definition := range page.Value {
			ids = append(ids, *definition.ID)
		}
		return pager.More(), nil
	})
	require.NoError(t, err)
	assert.Equal(t, 2, calls)
	assert.Equal(t, 1, retries)
	assert.Equal(t, []string{"custom"}, ids)
}

func TestPolicySDKPagerErrors(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			options := azurecloud.Resolve("").ARMClientOptions()
			calls := 0
			options.Transport = azuretest.TransportFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				return azuretest.JSONResponse(req, status, `{"error":{"code":"denied"}}`), nil
			})
			pager, err := newPolicyDefinitionsPager("sub", &azuretest.Credential{}, options)
			require.NoError(t, err)
			_, err = pager.NextPage(context.Background())
			var responseError *azcore.ResponseError
			require.ErrorAs(t, err, &responseError)
			assert.Equal(t, status, responseError.StatusCode)
			assert.Equal(t, 1, calls)
		})
	}
}

func TestPolicySDKPagerMalformedEnvelope(t *testing.T) {
	options := azurecloud.Resolve("").ARMClientOptions()
	options.Transport = azuretest.TransportFunc(func(req *http.Request) (*http.Response, error) {
		return azuretest.JSONResponse(req, http.StatusOK, `{"value":[`), nil
	})
	pager, err := newPolicyDefinitionsPager("sub", &azuretest.Credential{}, options)
	require.NoError(t, err)
	_, err = pager.NextPage(context.Background())
	var syntaxError *json.SyntaxError
	require.ErrorAs(t, err, &syntaxError)
}
