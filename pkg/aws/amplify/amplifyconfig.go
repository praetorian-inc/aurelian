package amplify

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Config holds all extracted Amplify/AWS configuration values.
type Config struct {
	URL                       string         `json:"url"`
	Region                    string         `json:"region,omitempty"`
	UserPoolID                string         `json:"user_pool_id,omitempty"`
	UserPoolClientID          string         `json:"user_pool_client_id,omitempty"`
	IdentityPoolID            string         `json:"identity_pool_id,omitempty"`
	OAuthDomain               string         `json:"oauth_domain,omitempty"`
	OAuthScopes               []string       `json:"oauth_scopes,omitempty"`
	OAuthRedirectSignIn       []string       `json:"oauth_redirect_sign_in,omitempty"`
	OAuthRedirectSignOut      []string       `json:"oauth_redirect_sign_out,omitempty"`
	OAuthResponseType         string         `json:"oauth_response_type,omitempty"`
	APIEndpoints              []string       `json:"api_endpoints,omitempty"`
	APIGatewayAPIKeys         []string       `json:"api_gateway_api_keys,omitempty"`
	LambdaFunctionURLs        []string       `json:"lambda_function_urls,omitempty"`
	GraphQLEndpoint           string         `json:"graphql_endpoint,omitempty"`
	AppSyncAPIKey             string         `json:"appsync_api_key,omitempty"`
	AppSyncAuthType           string         `json:"appsync_auth_type,omitempty"`
	S3Bucket                  string         `json:"s3_bucket,omitempty"`
	PinpointAppID             string         `json:"pinpoint_app_id,omitempty"`
	DynamoDBTables            []string       `json:"dynamodb_tables,omitempty"`
	CognitoMFA                string         `json:"cognito_mfa,omitempty"`
	CognitoUsernameAttributes []string       `json:"cognito_username_attributes,omitempty"`
	CognitoSignupAttributes   []string       `json:"cognito_signup_attributes,omitempty"`
	CloudLogicAPIs            []CloudLogicAPI `json:"cloud_logic_apis,omitempty"`
}

// CloudLogicAPI represents a single entry from aws_cloud_logic_custom.
type CloudLogicAPI struct {
	Name          string            `json:"name,omitempty"`
	Endpoint      string            `json:"endpoint"`
	Region        string            `json:"region,omitempty"`
	CustomHeaders map[string]string `json:"custom_headers,omitempty"`
}

// Extractor fetches and extracts Amplify configuration from web applications.
type Extractor struct {
	client *http.Client
}

const (
	fetchTimeout  = 15 * time.Second
	clientTimeout = 30 * time.Second
	maxBodySize   = 10 * 1024 * 1024 // 10 MB
	maxJSFetches  = 100
	defaultUA     = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
)

func NewExtractor() *Extractor {
	return &Extractor{
		client: &http.Client{Timeout: clientTimeout},
	}
}

// Extract fetches the target URL and all referenced JavaScript bundles,
// scanning for Amplify/AWS configuration values.
func (e *Extractor) Extract(ctx context.Context, target string) (Config, error) {
	result := Config{URL: target}

	if !strings.HasPrefix(target, "http") {
		target = "https://" + target
	}

	base, err := url.Parse(target)
	if err != nil {
		return result, fmt.Errorf("parsing URL: %w", err)
	}

	html, err := e.fetchURL(ctx, target)
	if err != nil {
		return result, fmt.Errorf("fetching HTML: %w", err)
	}

	applySingleExtractors(&result, html)
	applyMultiExtractors(&result, html)
	extractCloudLogicCustom(&result, html)

	jsURLs := collectScriptURLs(base, html)
	for _, path := range wellKnownConfigPaths {
		resolved := base.ResolveReference(&url.URL{Path: path})
		jsURLs = append(jsURLs, resolved.String())
	}

	seen := make(map[string]struct{})
	fetched := 0
	for i := 0; i < len(jsURLs) && fetched < maxJSFetches; i++ {
		jsURL := jsURLs[i]
		if _, ok := seen[jsURL]; ok {
			continue
		}
		seen[jsURL] = struct{}{}

		body, err := e.fetchURL(ctx, jsURL)
		if err != nil {
			continue
		}
		fetched++

		applySingleExtractors(&result, body)
		applyMultiExtractors(&result, body)
		extractCloudLogicCustom(&result, body)

		for _, m := range jsChunkRe.FindAllStringSubmatch(body, -1) {
			chunkURL := base.ResolveReference(&url.URL{Path: m[1]}).String()
			if _, ok := seen[chunkURL]; !ok {
				jsURLs = append(jsURLs, chunkURL)
			}
		}
	}

	return result, nil
}

// ValidationResult holds the outcome of probing a single endpoint.
type ValidationResult struct {
	Target     string `json:"target"`
	Type       string `json:"type"`       // "appsync", "api_gateway", "lambda"
	StatusCode int    `json:"status_code"`
	Body       string `json:"body,omitempty"`
	AuthMethod string `json:"auth_method"` // "none", "api_key", "custom_headers"
	KeyPreview string `json:"key_preview,omitempty"`
	Open       bool   `json:"open"`
	Valid      bool   `json:"valid"`
	Message    string `json:"message"`
}

// Validate probes all extracted endpoints and returns structured results.
func (e *Extractor) Validate(ctx context.Context, c Config) []ValidationResult {
	var results []ValidationResult

	if c.GraphQLEndpoint != "" && c.AppSyncAPIKey != "" {
		results = append(results, e.validateAppSync(ctx, c.GraphQLEndpoint, c.AppSyncAPIKey))
	}

	for _, endpoint := range c.APIEndpoints {
		var customHeaders map[string]string
		for _, api := range c.CloudLogicAPIs {
			if api.Endpoint == endpoint && len(api.CustomHeaders) > 0 {
				customHeaders = api.CustomHeaders
				break
			}
		}
		results = append(results, e.validateAPIGateway(ctx, endpoint, c.APIGatewayAPIKeys, customHeaders)...)
	}

	for _, fnURL := range c.LambdaFunctionURLs {
		results = append(results, e.validateLambda(ctx, fnURL))
	}

	return results
}

func (e *Extractor) validateAppSync(ctx context.Context, endpoint, apiKey string) ValidationResult {
	status, body := e.probeEndpoint(ctx, http.MethodPost, endpoint, http.Header{
		"Content-Type": {"application/json"},
		"x-api-key":    {apiKey},
	}, strings.NewReader(`{"query":"{ __typename }"}`))

	r := ValidationResult{
		Target:     endpoint,
		Type:       "appsync",
		StatusCode: status,
		Body:       truncate(body, 200),
		AuthMethod: "api_key",
		KeyPreview: maskKey(apiKey),
	}

	switch status {
	case http.StatusOK:
		r.Valid = true
		r.Message = "AppSync API key is VALID"
	case http.StatusUnauthorized, http.StatusForbidden:
		r.Message = fmt.Sprintf("AppSync API key is INVALID (HTTP %d)", status)
	case 0:
		r.Message = fmt.Sprintf("request failed: %s", body)
	default:
		r.Message = fmt.Sprintf("unexpected response (HTTP %d)", status)
	}
	return r
}

func (e *Extractor) validateAPIGateway(ctx context.Context, endpoint string, apiKeys []string, customHeaders map[string]string) []ValidationResult {
	var results []ValidationResult

	// Probe without auth.
	status, body := e.probeEndpoint(ctx, http.MethodGet, endpoint, nil, nil)
	r := ValidationResult{
		Target:     endpoint,
		Type:       "api_gateway",
		StatusCode: status,
		Body:       truncate(body, 200),
		AuthMethod: "none",
	}
	switch status {
	case http.StatusOK:
		r.Open = true
		r.Message = "endpoint is OPEN (no auth required)"
		return append(results, r)
	case http.StatusForbidden:
		r.Message = "endpoint returns HTTP 403 (auth required)"
	case http.StatusUnauthorized:
		r.Message = "endpoint returns HTTP 401 (auth required)"
	default:
		r.Message = fmt.Sprintf("endpoint returns HTTP %d", status)
	}
	results = append(results, r)

	// Try each API key.
	for _, key := range apiKeys {
		keyStatus, keyBody := e.probeEndpoint(ctx, http.MethodGet, endpoint, http.Header{
			"x-api-key": {key},
		}, nil)
		kr := ValidationResult{
			Target:     endpoint,
			Type:       "api_gateway",
			StatusCode: keyStatus,
			Body:       truncate(keyBody, 200),
			AuthMethod: "api_key",
			KeyPreview: maskKey(key),
		}
		switch keyStatus {
		case http.StatusOK:
			kr.Valid = true
			kr.Message = "API key is VALID"
		case http.StatusForbidden, http.StatusUnauthorized:
			kr.Message = fmt.Sprintf("API key rejected (HTTP %d)", keyStatus)
		default:
			kr.Message = fmt.Sprintf("API key returned HTTP %d", keyStatus)
		}
		results = append(results, kr)
	}

	// Try custom headers.
	if len(customHeaders) > 0 {
		h := make(http.Header)
		headerNames := make([]string, 0, len(customHeaders))
		for k, v := range customHeaders {
			h.Set(k, v)
			headerNames = append(headerNames, k)
		}
		chStatus, chBody := e.probeEndpoint(ctx, http.MethodGet, endpoint, h, nil)
		cr := ValidationResult{
			Target:     endpoint,
			Type:       "api_gateway",
			StatusCode: chStatus,
			Body:       truncate(chBody, 200),
			AuthMethod: "custom_headers",
			KeyPreview: strings.Join(headerNames, ", "),
		}
		switch chStatus {
		case http.StatusOK:
			cr.Valid = true
			cr.Message = "custom headers accepted"
		case http.StatusForbidden, http.StatusUnauthorized:
			cr.Message = fmt.Sprintf("custom headers rejected (HTTP %d)", chStatus)
		default:
			cr.Message = fmt.Sprintf("custom headers returned HTTP %d", chStatus)
		}
		results = append(results, cr)
	}

	return results
}

func (e *Extractor) validateLambda(ctx context.Context, fnURL string) ValidationResult {
	status, body := e.probeEndpoint(ctx, http.MethodGet, fnURL, nil, nil)
	r := ValidationResult{
		Target:     fnURL,
		Type:       "lambda",
		StatusCode: status,
		Body:       truncate(body, 200),
		AuthMethod: "none",
	}
	switch status {
	case http.StatusOK:
		r.Open = true
		r.Message = "Lambda URL is OPEN (IAM auth disabled)"
	case http.StatusForbidden:
		r.Message = "Lambda URL requires IAM auth (HTTP 403)"
	case http.StatusUnauthorized:
		r.Message = "Lambda URL requires auth (HTTP 401)"
	default:
		r.Message = fmt.Sprintf("Lambda URL returned HTTP %d", status)
	}
	return r
}

func maskKey(key string) string {
	if len(key) <= 8 {
		return key
	}
	return key[:4] + "..." + key[len(key)-4:]
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// FormatConfig returns a human-readable summary of the extracted config.
func FormatConfig(c Config) []string {
	var lines []string
	field := func(label, value string) {
		if value != "" {
			lines = append(lines, fmt.Sprintf("  %-28s %s", label+":", value))
		}
	}
	slice := func(label string, values []string) {
		if len(values) > 0 {
			lines = append(lines, fmt.Sprintf("  %-28s %s", label+":", strings.Join(values, ", ")))
		}
	}

	field("Region", c.Region)
	field("User Pool ID", c.UserPoolID)
	field("User Pool Client ID", c.UserPoolClientID)
	field("Identity Pool ID", c.IdentityPoolID)
	field("OAuth Domain", c.OAuthDomain)
	field("OAuth Response Type", c.OAuthResponseType)
	slice("OAuth Scopes", c.OAuthScopes)
	slice("OAuth Redirect Sign In", c.OAuthRedirectSignIn)
	slice("OAuth Redirect Sign Out", c.OAuthRedirectSignOut)
	field("GraphQL Endpoint", c.GraphQLEndpoint)
	field("AppSync API Key", c.AppSyncAPIKey)
	field("AppSync Auth Type", c.AppSyncAuthType)
	slice("API Endpoints", c.APIEndpoints)
	slice("API Gateway API Keys", c.APIGatewayAPIKeys)
	slice("Lambda Function URLs", c.LambdaFunctionURLs)
	field("S3 Bucket", c.S3Bucket)
	field("Pinpoint App ID", c.PinpointAppID)
	slice("DynamoDB Tables", c.DynamoDBTables)
	field("Cognito MFA", c.CognitoMFA)
	slice("Cognito Username Attributes", c.CognitoUsernameAttributes)
	slice("Cognito Signup Attributes", c.CognitoSignupAttributes)

	for _, api := range c.CloudLogicAPIs {
		lines = append(lines, "")
		label := api.Name
		if label == "" {
			label = "(unnamed)"
		}
		lines = append(lines, fmt.Sprintf("  Cloud Logic API [%s]:", label))
		lines = append(lines, fmt.Sprintf("    %-24s %s", "Endpoint:", api.Endpoint))
		if api.Region != "" {
			lines = append(lines, fmt.Sprintf("    %-24s %s", "Region:", api.Region))
		}
		for k, v := range api.CustomHeaders {
			lines = append(lines, fmt.Sprintf("    %-24s %s: %s", "Custom Header:", k, v))
		}
	}

	return lines
}

// probeEndpoint sends an HTTP request and returns the status code and response body.
func (e *Extractor) probeEndpoint(ctx context.Context, method, endpoint string, headers http.Header, body io.Reader) (int, string) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return 0, fmt.Sprintf("request error: %v", err)
	}

	req.Header.Set("User-Agent", defaultUA)
	for k, vals := range headers {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return 0, fmt.Sprintf("request error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	return resp.StatusCode, string(respBody)
}

type singleExtractor struct {
	setter   func(*Config, string)
	patterns []*regexp.Regexp
}

type multiExtractor struct {
	splitOnComma bool
	appender     func(*Config, string)
	patterns     []*regexp.Regexp
}

var singleExtractors = []singleExtractor{
	{
		setter: func(c *Config, v string) { c.Region = v },
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`["']?aws_(?:project|cognito)_region["']?\s*[=:]\s*["']([a-z]{2}-[a-z]+-\d)["']`),
			regexp.MustCompile(`["']?region["']?\s*:\s*["']([a-z]{2}-[a-z]+-\d)["']`),
		},
	},
	{
		setter: func(c *Config, v string) { c.UserPoolID = v },
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`["']?aws_user_pools_id["']?\s*[=:]\s*["']([a-z]{2}-[a-z]+-\d_[A-Za-z0-9]+)["']`),
			regexp.MustCompile(`["']?userPoolId["']?\s*[=:]\s*["']([a-z]{2}-[a-z]+-\d_[A-Za-z0-9]+)["']`),
			regexp.MustCompile(`[Pp]ool(?:Id|_id)["']?\s*[=:]\s*["']([a-z]{2}-[a-z]+-\d_[A-Za-z0-9]+)["']`),
		},
	},
	{
		setter: func(c *Config, v string) { c.UserPoolClientID = v },
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`["']?aws_user_pools_web_client_id["']?\s*[=:]\s*["']([a-z0-9]{20,30})["']`),
			regexp.MustCompile(`["']?userPoolWebClientId["']?\s*[=:]\s*["']([a-z0-9]{20,30})["']`),
			regexp.MustCompile(`[Cc]lient(?:Id|_id)["']?\s*[=:]\s*["']([a-z0-9]{20,30})["']`),
		},
	},
	{
		setter: func(c *Config, v string) { c.IdentityPoolID = v },
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`["']?aws_cognito_identity_pool_id["']?\s*[=:]\s*["']([a-z]{2}-[a-z]+-\d:[0-9a-f-]{36})["']`),
			regexp.MustCompile(`["']?identityPoolId["']?\s*[=:]\s*["']([a-z]{2}-[a-z]+-\d:[0-9a-f-]{36})["']`),
			regexp.MustCompile(`[Ii]dentity[Pp]ool(?:Id|_id)["']?\s*[=:]\s*["']([a-z]{2}-[a-z]+-\d:[0-9a-f-]{36})["']`),
		},
	},
	{
		setter: func(c *Config, v string) { c.OAuthDomain = v },
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`["']?(?:oauth|OAuth).*?[Dd]omain["']?\s*[=:]\s*["']([a-z0-9-]+\.auth\.[a-z]{2}-[a-z]+-\d\.amazoncognito\.com)["']`),
			regexp.MustCompile(`(https?://[a-z0-9-]+\.auth\.[a-z]{2}-[a-z]+-\d\.amazoncognito\.com)`),
		},
	},
	{
		setter: func(c *Config, v string) { c.AppSyncAPIKey = v },
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`["']?(?:aws_appsync_apiKey|apiKey)["']?\s*[=:]\s*["'](da2-[a-z0-9]{26})["']`),
			regexp.MustCompile(`(da2-[a-z0-9]{26})`),
		},
	},
	{
		setter: func(c *Config, v string) { c.AppSyncAuthType = v },
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`["']?(?:aws_appsync_authenticationType|authenticationType)["']?\s*[=:]\s*["']((?:AMAZON_COGNITO_USER_POOLS|API_KEY|AWS_IAM|OPENID_CONNECT|AWS_LAMBDA))["']`),
		},
	},
	{
		setter: func(c *Config, v string) { c.OAuthResponseType = v },
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`["']?responseType["']?\s*[=:]\s*["'](code|token)["']`),
		},
	},
	{
		setter: func(c *Config, v string) { c.CognitoMFA = v },
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`["']?(?:aws_cognito_mfa_configuration|mfaConfiguration)["']?\s*[=:]\s*["'](OFF|ON|OPTIONAL)["']`),
		},
	},
	{
		setter: func(c *Config, v string) { c.GraphQLEndpoint = v },
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`["']?(?:aws_appsync_graphqlEndpoint|graphqlEndpoint)["']?\s*[=:]\s*["'](https://[a-z0-9]+\.appsync-api\.[a-z]{2}-[a-z]+-\d\.amazonaws\.com/graphql)["']`),
			regexp.MustCompile(`(https://[a-z0-9]+\.appsync-api\.[a-z]{2}-[a-z]+-\d\.amazonaws\.com/graphql)`),
		},
	},
	{
		setter: func(c *Config, v string) { c.S3Bucket = v },
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`["']?(?:aws_user_files_s3_bucket|bucket)["']?\s*[=:]\s*["']([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])["']`),
		},
	},
	{
		setter: func(c *Config, v string) { c.PinpointAppID = v },
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`["']?(?:aws_mobile_analytics_app_id|appId)["']?\s*[=:]\s*["']([a-f0-9]{32})["']`),
		},
	},
}

var multiExtractors = []multiExtractor{
	{
		appender: func(c *Config, v string) { c.APIEndpoints = appendUnique(c.APIEndpoints, v) },
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`["']?endpoint["']?\s*[=:]\s*["'](https://[a-z0-9]+\.execute-api\.[a-z]{2}-[a-z]+-\d\.amazonaws\.com[^"']*)["']`),
			regexp.MustCompile(`(https://[a-z0-9]+\.execute-api\.[a-z]{2}-[a-z]+-\d\.amazonaws\.com/[a-zA-Z0-9/_-]+)`),
		},
	},
	{
		appender: func(c *Config, v string) { c.APIGatewayAPIKeys = appendUnique(c.APIGatewayAPIKeys, v) },
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`["']?x-api-key["']?\s*[=:]\s*["']([A-Za-z0-9]{20,50})["']`),
			regexp.MustCompile(`["']?(?:api[Kk]ey|apiGatewayApiKey)["']?\s*[=:]\s*["']([A-Za-z0-9]{20,50})["']`),
		},
	},
	{
		appender: func(c *Config, v string) { c.LambdaFunctionURLs = appendUnique(c.LambdaFunctionURLs, v) },
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`(https://[a-z0-9]+\.lambda-url\.[a-z]{2}-[a-z]+-\d\.on\.aws/?)`),
			regexp.MustCompile(`["']?endpoint["']?\s*[=:]\s*["'](https://[a-z0-9]+\.lambda-url\.[a-z]{2}-[a-z]+-\d\.on\.aws[^"']*)["']`),
		},
	},
	{
		appender: func(c *Config, v string) { c.DynamoDBTables = appendUnique(c.DynamoDBTables, v) },
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`["']?tableName["']?\s*[=:]\s*["']([A-Za-z0-9_-]+)["']`),
		},
	},
	{
		appender: func(c *Config, v string) { c.OAuthScopes = appendUnique(c.OAuthScopes, v) },
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`["']((?:phone|email|openid|profile|aws\.cognito\.signin\.user\.admin))["']`),
		},
	},
	{
		splitOnComma: true,
		appender:     func(c *Config, v string) { c.OAuthRedirectSignIn = appendUnique(c.OAuthRedirectSignIn, v) },
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`["']?redirectSignIn["']?\s*[=:]\s*["']([^"']+)["']`),
		},
	},
	{
		splitOnComma: true,
		appender:     func(c *Config, v string) { c.OAuthRedirectSignOut = appendUnique(c.OAuthRedirectSignOut, v) },
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`["']?redirectSignOut["']?\s*[=:]\s*["']([^"']+)["']`),
		},
	},
	{
		appender: func(c *Config, v string) { c.CognitoUsernameAttributes = appendUnique(c.CognitoUsernameAttributes, v) },
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`["']?(?:aws_cognito_username_attributes|usernameAttributes)["']?\s*[=:].*?["'](EMAIL|PHONE_NUMBER)["']`),
		},
	},
	{
		appender: func(c *Config, v string) { c.CognitoSignupAttributes = appendUnique(c.CognitoSignupAttributes, v) },
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`["']?(?:aws_cognito_signup_attributes|signupAttributes)["']?\s*[=:].*?["'](EMAIL|PHONE_NUMBER|NAME|PREFERRED_USERNAME)["']`),
		},
	},
}

var (
	scriptSrcRe = regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	jsChunkRe   = regexp.MustCompile(`["'](/static/js/[^"']+\.js)["']`)

	cloudLogicBlockRe = regexp.MustCompile(`(?:aws_cloud_logic_custom|cloud_logic_custom)["']?\s*[=:]\s*\[([^\]]+)\]`)
	cloudLogicEntryRe = regexp.MustCompile(`\{([^}]+)\}`)
	cloudLogicFieldRe = regexp.MustCompile(`["']?(\w+)["']?\s*[=:]\s*["']([^"']+)["']`)
	customHeaderRe    = regexp.MustCompile(`["']([A-Za-z][\w-]*)["']\s*:\s*["']([^"']+)["']`)
	headerBlockRe     = regexp.MustCompile(`custom_header\s*:\s*(?:async\s+)?(?:function\s*\(\s*\)|(?:\(\s*\)))\s*=>?\s*\(?(\{[^}]+\})\)?`)
)

var wellKnownConfigPaths = []string{
	"/aws-exports.js",
	"/amplifyconfiguration.json",
	"/amplify-config.js",
	"/runtime-config.js",
}

func (e *Extractor) fetchURL(ctx context.Context, target string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", defaultUA)

	resp, err := e.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return "", fmt.Errorf("reading body: %w", err)
	}

	return string(body), nil
}

func collectScriptURLs(base *url.URL, html string) []string {
	var urls []string
	for _, m := range scriptSrcRe.FindAllStringSubmatch(html, -1) {
		urls = append(urls, resolveURLRef(base, m[1]))
	}
	return urls
}

func resolveURLRef(base *url.URL, raw string) string {
	ref, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return base.ResolveReference(ref).String()
}

func applySingleExtractors(c *Config, body string) {
	for _, ext := range singleExtractors {
		for _, pat := range ext.patterns {
			if m := pat.FindStringSubmatch(body); len(m) > 1 && m[1] != "" {
				ext.setter(c, m[1])
			}
		}
	}
}

func applyMultiExtractors(c *Config, body string) {
	for _, ext := range multiExtractors {
		for _, pat := range ext.patterns {
			for _, m := range pat.FindAllStringSubmatch(body, -1) {
				if len(m) <= 1 || m[1] == "" {
					continue
				}
				val := m[1]
				if ext.splitOnComma {
					for _, part := range strings.Split(val, ",") {
						if part = strings.TrimSpace(part); part != "" {
							ext.appender(c, part)
						}
					}
				} else {
					ext.appender(c, val)
				}
			}
		}
	}
}

func extractCloudLogicCustom(c *Config, body string) {
	for _, block := range cloudLogicBlockRe.FindAllStringSubmatch(body, -1) {
		if len(block) < 2 {
			continue
		}
		for _, entry := range cloudLogicEntryRe.FindAllStringSubmatch(block[1], -1) {
			if len(entry) < 2 {
				continue
			}
			api := CloudLogicAPI{CustomHeaders: make(map[string]string)}

			for _, field := range cloudLogicFieldRe.FindAllStringSubmatch(entry[1], -1) {
				if len(field) < 3 {
					continue
				}
				switch strings.ToLower(field[1]) {
				case "name":
					api.Name = field[2]
				case "endpoint":
					api.Endpoint = field[2]
				case "region":
					api.Region = field[2]
				}
			}

			if api.Endpoint == "" {
				continue
			}

			c.APIEndpoints = appendUnique(c.APIEndpoints, api.Endpoint)
			c.CloudLogicAPIs = append(c.CloudLogicAPIs, api)
		}
	}

	extractCustomHeaders(c, body)
}

func extractCustomHeaders(c *Config, body string) {
	for _, m := range headerBlockRe.FindAllStringSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		for _, h := range customHeaderRe.FindAllStringSubmatch(m[1], -1) {
			if len(h) < 3 {
				continue
			}
			key, val := h[1], h[2]

			if strings.EqualFold(key, "x-api-key") {
				c.APIGatewayAPIKeys = appendUnique(c.APIGatewayAPIKeys, val)
			}

			// Best-effort: associate headers with the most recently parsed API entry,
			// since custom_header blocks typically follow their API definition.
			if len(c.CloudLogicAPIs) > 0 {
				last := &c.CloudLogicAPIs[len(c.CloudLogicAPIs)-1]
				last.CustomHeaders[key] = val
			}
		}
	}
}

func appendUnique(slice []string, val string) []string {
	if !slices.Contains(slice, val) {
		return append(slice, val)
	}
	return slice
}
