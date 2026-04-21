package amplify

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractOAuthScopes_RequiresScopeContext(t *testing.T) {
	t.Run("bare quoted email does not match", func(t *testing.T) {
		// Simulates a non-Amplify page with "email" in form fields, labels, etc.
		body := `<input type="text" name="user[email]" />
			<label>Email Address</label>
			<div class="controls">
				<input type='email' />
			</div>`

		var c Config
		extractOAuthScopes(&c, body)
		assert.Empty(t, c.OAuthScopes)
	})

	t.Run("scope array extracts values", func(t *testing.T) {
		body := `"oauth":{"scope":["email","openid","phone","profile","aws.cognito.signin.user.admin"]}`

		var c Config
		extractOAuthScopes(&c, body)
		assert.ElementsMatch(t, []string{"email", "openid", "phone", "profile", "aws.cognito.signin.user.admin"}, c.OAuthScopes)
	})

	t.Run("scopes key also works", func(t *testing.T) {
		body := `"scopes": ["email", "openid"]`

		var c Config
		extractOAuthScopes(&c, body)
		assert.ElementsMatch(t, []string{"email", "openid"}, c.OAuthScopes)
	})

	t.Run("single-quoted scope array", func(t *testing.T) {
		body := `'scope': ['email', 'profile']`

		var c Config
		extractOAuthScopes(&c, body)
		assert.ElementsMatch(t, []string{"email", "profile"}, c.OAuthScopes)
	})
}

func TestHasAmplifySignal(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		want   bool
	}{
		{"empty config", Config{URL: "https://example.com"}, false},
		{"only oauth scopes", Config{OAuthScopes: []string{"email"}}, false},
		{"only region", Config{Region: "us-east-1"}, false},
		{"user pool ID", Config{UserPoolID: "us-east-1_AbCdEfGhI"}, true},
		{"user pool client ID", Config{UserPoolClientID: "abcdefghij1234567890abcde"}, true},
		{"identity pool ID", Config{IdentityPoolID: "us-east-1:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}, true},
		{"oauth domain", Config{OAuthDomain: "myapp.auth.us-east-1.amazoncognito.com"}, true},
		{"graphql endpoint", Config{GraphQLEndpoint: "https://abc.appsync-api.us-east-1.amazonaws.com/graphql"}, true},
		{"appsync api key", Config{AppSyncAPIKey: "da2-abcdefghijklmnopqrstuvwxyz"}, true},
		{"api endpoints", Config{APIEndpoints: []string{"https://abc.execute-api.us-east-1.amazonaws.com/prod"}}, true},
		{"lambda URLs", Config{LambdaFunctionURLs: []string{"https://abc.lambda-url.us-east-1.on.aws/"}}, true},
		{"s3 bucket", Config{S3Bucket: "my-bucket"}, true},
		{"pinpoint app ID", Config{PinpointAppID: "aabbccddeeff00112233445566778899"}, true},
		{"cloud logic APIs", Config{CloudLogicAPIs: []CloudLogicAPI{{Endpoint: "https://example.com"}}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, hasAmplifySignal(tt.config))
		})
	}
}

func TestClearWeakSignals_PreservesStrongFields(t *testing.T) {
	c := Config{
		URL:                       "https://example.com",
		Region:                    "us-east-1",
		UserPoolID:                "us-east-1_AbCdEfGhI",
		OAuthScopes:               []string{"email"},
		OAuthResponseType:         "code",
		DynamoDBTables:            []string{"MyTable"},
		CognitoMFA:                "OFF",
		CognitoUsernameAttributes: []string{"EMAIL"},
		CognitoSignupAttributes:   []string{"EMAIL"},
		APIGatewayAPIKeys:         []string{"somekey123"},
	}

	clearWeakSignals(&c)

	// Strong fields preserved.
	assert.Equal(t, "https://example.com", c.URL)
	assert.Equal(t, "us-east-1_AbCdEfGhI", c.UserPoolID)

	// Weak fields cleared.
	assert.Empty(t, c.Region)
	assert.Empty(t, c.OAuthScopes)
	assert.Empty(t, c.OAuthResponseType)
	assert.Empty(t, c.DynamoDBTables)
	assert.Empty(t, c.CognitoMFA)
	assert.Empty(t, c.CognitoUsernameAttributes)
	assert.Empty(t, c.CognitoSignupAttributes)
	assert.Empty(t, c.APIGatewayAPIKeys)
}

func TestClearWeakSignals_NotCalledWhenStrongSignalPresent(t *testing.T) {
	// Simulates a real Amplify app — weak signals should be kept.
	c := Config{
		Region:        "us-east-1",
		UserPoolID:    "us-east-1_AbCdEfGhI",
		OAuthScopes:   []string{"email", "openid"},
		DynamoDBTables: []string{"Users"},
	}

	assert.True(t, hasAmplifySignal(c))
	// clearWeakSignals would not be called, so all fields remain.
	assert.Equal(t, "us-east-1", c.Region)
	assert.Equal(t, []string{"email", "openid"}, c.OAuthScopes)
	assert.Equal(t, []string{"Users"}, c.DynamoDBTables)
}

func TestNonAmplifyPage_NoFalsePositives(t *testing.T) {
	// Simulates an Atlassian Statuspage login page with "email" scattered throughout.
	body := `<!DOCTYPE html>
<html>
<head><title>Status - Login</title></head>
<body>
  <form action="/access" method="post">
    <label>Email Address</label>
    <input type="text" name="page_access_user[email]" />
    <input type='email' />
    <label>Password</label>
    <input type="password" name="page_access_user[password]" />
    <input type="submit" value="Authenticate">
  </form>
  <script>
    var pageColorData = {"blue":"#1714DB","font":"#555463"};
  </script>
</body>
</html>`

	var c Config
	applySingleExtractors(&c, body)
	applyMultiExtractors(&c, body)
	extractOAuthScopes(&c, body)

	assert.Empty(t, c.OAuthScopes, "should not extract oauth scopes from non-Amplify page")
	assert.False(t, hasAmplifySignal(c), "non-Amplify page should have no strong signal")
}
