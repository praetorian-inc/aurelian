//go:build integration

package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/aws/amplify"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testAmplifyHTML returns an HTML page with embedded Amplify config and a script tag
// referencing a JS bundle at the given path.
func testAmplifyHTML(jsBundlePath string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <script>
    var awsConfig = {
      "aws_project_region": "us-east-1",
      "aws_cognito_identity_pool_id": "us-east-1:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      "aws_user_pools_id": "us-east-1_AbCdEfGhI",
      "aws_user_pools_web_client_id": "abcdefghij1234567890abcde",
      "aws_cognito_mfa_configuration": "OPTIONAL",
      "aws_cognito_signup_attributes": ["EMAIL"],
      "aws_cognito_username_attributes": ["EMAIL"]
    };
  </script>
  <script src="%s"></script>
</head>
<body></body>
</html>`, jsBundlePath)
}

// testAmplifyJS returns a JS bundle containing additional Amplify config values
// that would typically be found in webpack/vite bundles.
func testAmplifyJS() string {
	// Use minified format for the OAuth block so the oauth.*?domain regex
	// matches on a single line (the regex's .*? does not cross newlines).
	return `
// Bundled Amplify configuration
var amplifyConfig = {
  "aws_appsync_graphqlEndpoint": "https://abc123def4.appsync-api.us-east-1.amazonaws.com/graphql",
  "aws_appsync_apiKey": "da2-abcdefghijklmnopqrstuvwxyz",
  "aws_appsync_authenticationType": "API_KEY",
  "oauth":{"domain":"myapp-auth.auth.us-east-1.amazoncognito.com","redirectSignIn":"https://myapp.example.com/callback","redirectSignOut":"https://myapp.example.com/logout","responseType":"code"},
  "aws_cloud_logic_custom": [{"name":"myapi","endpoint":"https://abc123def4.execute-api.us-east-1.amazonaws.com/prod","region":"us-east-1"}],
  "aws_user_files_s3_bucket": "myapp-uploads-bucket-12345",
  "aws_mobile_analytics_app_id": "aabbccddeeff00112233445566778899"
};
`
}

func TestAmplifyConfig(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, testAmplifyHTML("/static/js/main.js"))
	})
	mux.HandleFunc("/static/js/main.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, testAmplifyJS())
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "amplify-config")
	if !ok {
		t.Fatal("amplify-config module not registered in plugin system")
	}

	cfg := plugin.Config{
		Args: map[string]any{
			"url": srv.URL,
		},
		Context: context.Background(),
	}

	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	results, err := p2.Collect()
	require.NoError(t, err)
	require.Len(t, results, 1, "expected exactly one AnalyzeResult")

	ar, ok := results[0].(output.AnalyzeResult)
	require.True(t, ok, "result should be output.AnalyzeResult, got %T", results[0])

	assert.Equal(t, "amplify-config", ar.Module)
	assert.Equal(t, srv.URL, ar.Input)

	var config amplify.Config
	require.NoError(t, json.Unmarshal(ar.Results, &config))

	// --- Cognito fields extracted from HTML ---

	t.Run("extracts region", func(t *testing.T) {
		assert.Equal(t, "us-east-1", config.Region)
	})

	t.Run("extracts Cognito user pool ID", func(t *testing.T) {
		assert.Equal(t, "us-east-1_AbCdEfGhI", config.UserPoolID)
	})

	t.Run("extracts Cognito user pool client ID", func(t *testing.T) {
		assert.Equal(t, "abcdefghij1234567890abcde", config.UserPoolClientID)
	})

	t.Run("extracts Cognito identity pool ID", func(t *testing.T) {
		assert.Equal(t, "us-east-1:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", config.IdentityPoolID)
	})

	t.Run("extracts Cognito MFA configuration", func(t *testing.T) {
		assert.Equal(t, "OPTIONAL", config.CognitoMFA)
	})

	t.Run("extracts Cognito signup attributes", func(t *testing.T) {
		assert.Contains(t, config.CognitoSignupAttributes, "EMAIL")
	})

	t.Run("extracts Cognito username attributes", func(t *testing.T) {
		assert.Contains(t, config.CognitoUsernameAttributes, "EMAIL")
	})

	// --- AppSync fields extracted from JS bundle ---

	t.Run("extracts AppSync GraphQL endpoint", func(t *testing.T) {
		assert.Equal(t, "https://abc123def4.appsync-api.us-east-1.amazonaws.com/graphql", config.GraphQLEndpoint)
	})

	t.Run("extracts AppSync API key", func(t *testing.T) {
		assert.Equal(t, "da2-abcdefghijklmnopqrstuvwxyz", config.AppSyncAPIKey)
	})

	t.Run("extracts AppSync auth type", func(t *testing.T) {
		assert.Equal(t, "API_KEY", config.AppSyncAuthType)
	})

	// --- OAuth fields from JS bundle ---

	t.Run("extracts OAuth domain", func(t *testing.T) {
		assert.Equal(t, "myapp-auth.auth.us-east-1.amazoncognito.com", config.OAuthDomain)
	})

	t.Run("extracts OAuth redirect sign-in", func(t *testing.T) {
		assert.Contains(t, config.OAuthRedirectSignIn, "https://myapp.example.com/callback")
	})

	t.Run("extracts OAuth redirect sign-out", func(t *testing.T) {
		assert.Contains(t, config.OAuthRedirectSignOut, "https://myapp.example.com/logout")
	})

	t.Run("extracts OAuth response type", func(t *testing.T) {
		assert.Equal(t, "code", config.OAuthResponseType)
	})

	// --- API Gateway / Cloud Logic from JS bundle ---

	t.Run("extracts API Gateway endpoint", func(t *testing.T) {
		assert.Contains(t, config.APIEndpoints, "https://abc123def4.execute-api.us-east-1.amazonaws.com/prod")
	})

	t.Run("extracts Cloud Logic API entry", func(t *testing.T) {
		require.NotEmpty(t, config.CloudLogicAPIs, "expected at least one Cloud Logic API")
		found := false
		for _, api := range config.CloudLogicAPIs {
			if api.Name == "myapi" && api.Endpoint == "https://abc123def4.execute-api.us-east-1.amazonaws.com/prod" {
				assert.Equal(t, "us-east-1", api.Region)
				found = true
				break
			}
		}
		assert.True(t, found, "expected Cloud Logic API entry with name 'myapi'")
	})

	// --- S3 and Pinpoint from JS bundle ---

	t.Run("extracts S3 bucket", func(t *testing.T) {
		assert.Equal(t, "myapp-uploads-bucket-12345", config.S3Bucket)
	})

	t.Run("extracts Pinpoint app ID", func(t *testing.T) {
		assert.Equal(t, "aabbccddeeff00112233445566778899", config.PinpointAppID)
	})

	// --- URL is set on the result ---

	t.Run("result URL matches input", func(t *testing.T) {
		assert.Equal(t, srv.URL, config.URL)
	})
}

func TestAmplifyConfig_Validate(t *testing.T) {
	// Set up a mock API Gateway endpoint that returns 200 without auth.
	apiGW := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer apiGW.Close()

	// Serve HTML that references the mock API Gateway endpoint.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Embed config with the mock API GW endpoint directly in the HTML.
		fmt.Fprintf(w, `<!DOCTYPE html>
<html><head><script>
var config = {
  "aws_project_region": "us-east-1",
  "endpoint": "%s"
};
</script></head><body></body></html>`, apiGW.URL+"/prod")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "amplify-config")
	if !ok {
		t.Fatal("amplify-config module not registered in plugin system")
	}

	cfg := plugin.Config{
		Args: map[string]any{
			"url":      srv.URL,
			"validate": true,
		},
		Context: context.Background(),
	}

	results, err := collectResults(t, mod, cfg)
	require.NoError(t, err)
	require.Len(t, results, 1)

	ar, ok := results[0].(output.AnalyzeResult)
	require.True(t, ok)

	var config amplify.Config
	require.NoError(t, json.Unmarshal(ar.Results, &config))

	// The validation probes happen after extraction but don't change the
	// AnalyzeResult output — they only log. Verify extraction still works.
	assert.Equal(t, "us-east-1", config.Region)
}

func TestAmplifyConfig_EmptyPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html><html><head></head><body></body></html>`)
	}))
	defer srv.Close()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "amplify-config")
	if !ok {
		t.Fatal("amplify-config module not registered in plugin system")
	}

	cfg := plugin.Config{
		Args: map[string]any{
			"url": srv.URL,
		},
		Context: context.Background(),
	}

	results, err := collectResults(t, mod, cfg)
	require.NoError(t, err)
	require.Len(t, results, 1, "should still emit a result even with no config found")

	ar, ok := results[0].(output.AnalyzeResult)
	require.True(t, ok)

	var config amplify.Config
	require.NoError(t, json.Unmarshal(ar.Results, &config))

	// All config fields should be empty/zero.
	assert.Empty(t, config.Region)
	assert.Empty(t, config.UserPoolID)
	assert.Empty(t, config.GraphQLEndpoint)
	assert.Empty(t, config.APIEndpoints)
	assert.Empty(t, config.CloudLogicAPIs)
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

	results, err := collectResults(t, mod, cfg)
	require.NoError(t, err, "module should not return an error for unreachable URLs")
	assert.Empty(t, results, "should emit no results when the target is unreachable")
}

func collectResults(t *testing.T, mod plugin.Module, cfg plugin.Config) ([]model.AurelianModel, error) {
	t.Helper()
	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)
	return p2.Collect()
}
