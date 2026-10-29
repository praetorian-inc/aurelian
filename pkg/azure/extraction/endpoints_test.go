package extraction

import (
	"context"
	"net/http"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appconfiguration/armappconfiguration/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos/v3"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/test/azuretest"
)

func TestDataPlaneEndpoints(t *testing.T) {
	const propertyEndpoint = "https://from-properties.example.test/"
	const sdkEndpoint = "https://from-sdk.example.test/"

	for _, service := range []struct {
		name       string
		properties map[string]any
		response   string
		path       string
		resolve    func(*testing.T, *arm.ClientOptions, *azuretest.Credential, map[string]any) (string, error)
	}{
		{
			name:       "blob",
			properties: map[string]any{"primaryEndpoints": map[string]any{"blob": propertyEndpoint}},
			response:   `{"properties":{"primaryEndpoints":{"blob":"` + sdkEndpoint + `"}}}`,
			path:       "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/account",
			resolve: func(t *testing.T, options *arm.ClientOptions, cred *azuretest.Credential, properties map[string]any) (string, error) {
				client, err := armstorage.NewAccountsClient("sub", cred, options)
				require.NoError(t, err)
				return resolveStorageBlobEndpoint(context.Background(), client, "rg", "account", properties)
			},
		},
		{
			name:       "cosmos",
			properties: map[string]any{"documentEndpoint": propertyEndpoint},
			response:   `{"properties":{"documentEndpoint":"` + sdkEndpoint + `"}}`,
			path:       "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/account",
			resolve: func(t *testing.T, options *arm.ClientOptions, cred *azuretest.Credential, properties map[string]any) (string, error) {
				client, err := armcosmos.NewDatabaseAccountsClient("sub", cred, options)
				require.NoError(t, err)
				return resolveCosmosDocumentEndpoint(context.Background(), client, "rg", "account", properties)
			},
		},
		{
			name:       "app configuration",
			properties: map[string]any{"endpoint": propertyEndpoint},
			response:   `{"properties":{"endpoint":"` + sdkEndpoint + `"}}`,
			path:       "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.AppConfiguration/configurationStores/store",
			resolve: func(t *testing.T, options *arm.ClientOptions, cred *azuretest.Credential, properties map[string]any) (string, error) {
				client, err := armappconfiguration.NewConfigurationStoresClient("sub", cred, options)
				require.NoError(t, err)
				return resolveAppConfigEndpoint(context.Background(), client, "rg", "store", properties)
			},
		},
	} {
		t.Run(service.name, func(t *testing.T) {
			for _, tc := range []struct {
				name       string
				properties map[string]any
				response   string
				status     int
				want       string
				calls      int
			}{
				{"properties avoid ARM call", service.properties, "", http.StatusOK, propertyEndpoint, 0},
				{"SDK fallback", nil, service.response, http.StatusOK, sdkEndpoint, 1},
				{"empty properties fallback", map[string]any{"endpoint": "", "documentEndpoint": "", "primaryEndpoints": map[string]any{"blob": ""}}, service.response, http.StatusOK, sdkEndpoint, 1},
				{"mistyped properties fallback", map[string]any{"endpoint": 123, "documentEndpoint": 123, "primaryEndpoints": "invalid"}, service.response, http.StatusOK, sdkEndpoint, 1},
				{"missing endpoint", nil, `{"properties":{}}`, http.StatusOK, "", 1},
				{"missing properties", nil, `{}`, http.StatusOK, "", 1},
				{"forbidden", nil, `{"error":{"code":"AuthorizationFailed"}}`, http.StatusForbidden, "", 1},
			} {
				t.Run(tc.name, func(t *testing.T) {
					cred := &azuretest.Credential{}
					options := azurecloud.Resolve("").ARMClientOptions()
					calls := 0
					options.Transport = azuretest.TransportFunc(func(req *http.Request) (*http.Response, error) {
						calls++
						assert.Equal(t, http.MethodGet, req.Method)
						assert.Equal(t, "management.azure.com", req.URL.Host)
						assert.Equal(t, service.path, req.URL.Path)
						return azuretest.JSONResponse(req, tc.status, tc.response), nil
					})

					endpoint, err := service.resolve(t, options, cred, tc.properties)
					if tc.want == "" {
						require.Error(t, err)
					} else {
						require.NoError(t, err)
					}
					if tc.status == http.StatusForbidden {
						var responseError *azcore.ResponseError
						require.ErrorAs(t, err, &responseError)
					}
					assert.Equal(t, tc.want, endpoint)
					assert.Equal(t, tc.calls, calls)
					if tc.calls == 0 {
						assert.Empty(t, cred.Scopes)
					}
				})
			}
		})
	}
}
