package extraction

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/aurelian/pkg/output"
)

func TestCosmosRegionalEndpointsStayAccountAndCloudSpecific(t *testing.T) {
	_, err := validateCosmosRegionalEndpoint("https://account-usgovvirginia.documents.azure.us/", "ACCOUNT", "documents.azure.us")
	require.NoError(t, err)
	for _, raw := range []string{"https://account.documents.azure.us/", "https://account-usgovvirginia.documents.azure.us:443/"} {
		_, err := validateCosmosRegionalEndpoint(raw, "account", "documents.azure.us")
		require.NoError(t, err)
	}
	for _, raw := range []string{"https://account-eastus.documents.azure.com/", "https://other-usgovvirginia.documents.azure.us/", "https://account-usgovvirginia.documents.azure.us.attacker/", "http://account-usgovvirginia.documents.azure.us/", "https://user@account-usgovvirginia.documents.azure.us/", "https://account-usgovvirginia.documents.azure.us/?sig=secret", "https://account-.documents.azure.us/"} {
		_, err := validateCosmosRegionalEndpoint(raw, "account", "documents.azure.us")
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "secret")
	}
}

func TestServiceReturnedEndpointsAreValidatedNotRewritten(t *testing.T) {
	const suffix = "documents.azure.us"
	const expected = "https://account.documents.azure.us"
	for _, raw := range []string{expected, expected + "/", expected + ":443/"} {
		got, err := resourceEndpoint(output.AzureResource{Properties: map[string]any{"documentEndpoint": raw}}, "account", suffix, "documentEndpoint")
		require.NoError(t, err)
		assert.Equal(t, expected, got)
	}
	for _, raw := range []any{"https://account.documents.azure.com/", "https://other.documents.azure.us/", "https://account.documents.azure.us.attacker/", "https://evil@account.documents.azure.us/", expected + "?sig=secret", expected + "/unexpected", expected + ":444/", 42, ""} {
		_, err := resourceEndpoint(output.AzureResource{Properties: map[string]any{"documentEndpoint": raw}}, "account", suffix, "documentEndpoint")
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "secret")
	}
	for _, resource := range []output.AzureResource{{}, {Properties: map[string]any{}}} {
		got, err := resourceEndpoint(resource, "account", suffix, "documentEndpoint")
		require.NoError(t, err)
		assert.Equal(t, expected, got)
	}
	got, err := resourceEndpoint(output.AzureResource{Properties: map[string]any{"primaryEndpoints": map[string]any{"blob": "https://account.blob.core.usgovcloudapi.net/"}}}, "account", "blob.core.usgovcloudapi.net", "primaryEndpoints", "blob")
	require.NoError(t, err)
	assert.Equal(t, "https://account.blob.core.usgovcloudapi.net", got)
}
