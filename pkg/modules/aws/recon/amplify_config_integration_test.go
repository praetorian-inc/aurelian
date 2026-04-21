//go:build integration

package recon

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/aws/amplify"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAmplifyConfig(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/amplify")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "amplify-config")
	if !ok {
		t.Fatal("amplify-config module not registered in plugin system")
	}

	mainURL := fixture.Output("main_url")

	cfg := plugin.Config{
		Args: map[string]any{
			"url": mainURL,
		},
		Context: context.Background(),
	}

	results, err := testutil.RunAndCollect(t, mod, cfg)
	require.NoError(t, err)
	require.Len(t, results, 1, "expected exactly one AnalyzeResult")

	ar, ok := results[0].(output.AnalyzeResult)
	require.True(t, ok, "result should be output.AnalyzeResult, got %T", results[0])
	assert.Equal(t, "amplify-config", ar.Module)
	assert.Equal(t, mainURL, ar.Input)

	var config amplify.Config
	require.NoError(t, json.Unmarshal(ar.Results, &config))

	t.Run("result URL matches input", func(t *testing.T) {
		assert.Equal(t, mainURL, config.URL)
	})

	t.Run("extracts region", func(t *testing.T) {
		assert.Equal(t, fixture.Output("expected_region"), config.Region)
	})

	t.Run("extracts user pool ID", func(t *testing.T) {
		assert.Equal(t, fixture.Output("expected_user_pool_id"), config.UserPoolID)
	})

	t.Run("extracts user pool client ID", func(t *testing.T) {
		assert.Equal(t, fixture.Output("expected_user_pool_client_id"), config.UserPoolClientID)
	})

	t.Run("extracts identity pool ID", func(t *testing.T) {
		assert.Equal(t, fixture.Output("expected_identity_pool_id"), config.IdentityPoolID)
	})

	t.Run("extracts Cognito MFA configuration", func(t *testing.T) {
		assert.Equal(t, "OPTIONAL", config.CognitoMFA)
	})

	t.Run("extracts Cognito sign-up attributes", func(t *testing.T) {
		assert.Contains(t, config.CognitoSignupAttributes, "EMAIL")
	})

	t.Run("extracts Cognito username attributes", func(t *testing.T) {
		assert.Contains(t, config.CognitoUsernameAttributes, "EMAIL")
	})

	t.Run("extracts AppSync GraphQL endpoint", func(t *testing.T) {
		assert.Equal(t, fixture.Output("expected_appsync_endpoint"), config.GraphQLEndpoint)
	})

	t.Run("extracts AppSync API key", func(t *testing.T) {
		assert.Equal(t, fixture.Output("expected_appsync_api_key"), config.AppSyncAPIKey)
	})

	t.Run("extracts AppSync auth type", func(t *testing.T) {
		assert.Equal(t, "API_KEY", config.AppSyncAuthType)
	})
}

func TestAmplifyConfig_UnreachableURL(t *testing.T) {
	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "amplify-config")
	if !ok {
		t.Fatal("amplify-config module not registered in plugin system")
	}

	cfg := plugin.Config{
		Args: map[string]any{
			"url": "http://127.0.0.1:1", // port 1 — connection refused
		},
		Context: context.Background(),
	}

	results, err := testutil.RunAndCollect(t, mod, cfg)
	require.NoError(t, err, "module should not return an error for unreachable URLs")
	assert.Empty(t, results, "should emit no results when the target is unreachable")
}
