package recon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"golang.org/x/oauth2/google"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&GCPWhoamiModule{})
}

type GCPWhoamiConfig struct {
	CredentialsFile string `param:"creds-file" desc:"Path to GCP credentials JSON" shortcode:"c"`
}

type GCPWhoamiModule struct {
	GCPWhoamiConfig
}

func (m *GCPWhoamiModule) ID() string                       { return "whoami" }
func (m *GCPWhoamiModule) Name() string                     { return "GCP Covert Whoami" }
func (m *GCPWhoamiModule) Platform() plugin.Platform        { return plugin.PlatformGCP }
func (m *GCPWhoamiModule) Category() plugin.Category        { return plugin.CategoryRecon }
func (m *GCPWhoamiModule) OpsecLevel() string               { return "stealth" }
func (m *GCPWhoamiModule) Authors() []string                { return []string{"Praetorian"} }
func (m *GCPWhoamiModule) SupportedResourceTypes() []string { return nil }
func (m *GCPWhoamiModule) Parameters() any                  { return &m.GCPWhoamiConfig }

func (m *GCPWhoamiModule) Description() string {
	return "Determine caller identity via the OAuth2 tokeninfo endpoint without generating GCP Cloud Audit Logs. " +
		"Supports service account keys, user credentials, and workload identity federation."
}

func (m *GCPWhoamiModule) References() []string {
	return []string{"https://cloud.google.com/docs/authentication/token-types"}
}

func (m *GCPWhoamiModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	ctx := cfg.Context

	if m.CredentialsFile != "" {
		os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", m.CredentialsFile)
	}

	creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return fmt.Errorf("whoami: find credentials: %w", err)
	}

	// Extract identity from the credential JSON (works for all types).
	// creds.JSON may be empty for some credential types (e.g., external_account),
	// so fall back to reading the file directly.
	credJSON := creds.JSON
	if len(credJSON) == 0 {
		credJSON = readCredentialFile(m.CredentialsFile)
	}
	credInfo := parseCredentialJSON(credJSON)

	token, err := creds.TokenSource.Token()
	if err != nil {
		return fmt.Errorf("whoami: get token: %w", err)
	}

	// Try tokeninfo for additional details (email, sub, scopes).
	tokenInfo := fetchTokenInfo(cfg, token.AccessToken)

	identity := mergeIdentity(credInfo, tokenInfo)

	if identity.Email != "" {
		cfg.Success("identity: %s", identity.Email)
	}
	if identity.ProjectID != "" {
		cfg.Success("project: %s", identity.ProjectID)
	}
	cfg.Success("type: %s", identity.CredType)
	if identity.Scopes != "" {
		cfg.Success("scopes: %s", identity.Scopes)
	}

	out.Send(&identity)
	return nil
}

func readCredentialFile(path string) []byte {
	if path == "" {
		path = os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	}
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return data
}

// credentialJSON captures identity fields from all GCP credential file types.
type credentialJSON struct {
	Type string `json:"type"`

	// service_account
	ProjectID    string `json:"project_id"`
	ClientEmail  string `json:"client_email"`
	ClientID     string `json:"client_id"`
	PrivateKeyID string `json:"private_key_id"`

	// authorized_user
	ClientSecret string `json:"client_secret"`

	// external_account (workload identity federation)
	ServiceAccountImpersonationURL string `json:"service_account_impersonation_url"`
	Audience                       string `json:"audience"`
}

func parseCredentialJSON(raw []byte) output.GCPCallerIdentity {
	var result output.GCPCallerIdentity
	result.Status = "success"

	if len(raw) == 0 {
		result.CredType = "application_default"
		return result
	}

	var cred credentialJSON
	if err := json.Unmarshal(raw, &cred); err != nil {
		result.CredType = "unknown"
		return result
	}

	result.CredType = cred.Type

	switch cred.Type {
	case "service_account":
		result.Email = cred.ClientEmail
		result.ProjectID = cred.ProjectID
		result.ClientID = cred.ClientID
	case "authorized_user":
		result.ClientID = cred.ClientID
	case "external_account":
		// Extract the impersonated SA email from the impersonation URL.
		result.Email = saEmailFromImpersonationURL(cred.ServiceAccountImpersonationURL)
		// Extract project ID from the audience field.
		result.ProjectID = projectIDFromAudience(cred.Audience)
	}

	return result
}

// saEmailFromImpersonationURL extracts the SA email from a URL like:
// https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/EMAIL:generateAccessToken
func saEmailFromImpersonationURL(url string) string {
	_, after, found := strings.Cut(url, "serviceAccounts/")
	if !found {
		return ""
	}
	email, _, _ := strings.Cut(after, ":")
	return email
}

// projectIDFromAudience extracts a project number from a WIF audience like:
// //iam.googleapis.com/projects/1044257231918/locations/global/workloadIdentityPools/...
func projectIDFromAudience(audience string) string {
	_, after, found := strings.Cut(audience, "projects/")
	if !found {
		return ""
	}
	projectID, _, _ := strings.Cut(after, "/")
	return projectID
}

type tokenInfoResponse struct {
	Email     string `json:"email"`
	Sub       string `json:"sub"`
	Scope     string `json:"scope"`
	ExpiresIn string `json:"expires_in"`
}

func fetchTokenInfo(cfg plugin.Config, accessToken string) *tokenInfoResponse {
	url := "https://oauth2.googleapis.com/tokeninfo?access_token=" + accessToken
	req, err := http.NewRequestWithContext(cfg.Context, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var info tokenInfoResponse
	if err := json.Unmarshal(body, &info); err != nil {
		return nil
	}
	return &info
}

// mergeIdentity combines credential file info with tokeninfo response,
// preferring tokeninfo values when present (they reflect the actual token).
func mergeIdentity(credInfo output.GCPCallerIdentity, tokenInfo *tokenInfoResponse) output.GCPCallerIdentity {
	if tokenInfo == nil {
		return credInfo
	}

	if tokenInfo.Email != "" {
		credInfo.Email = tokenInfo.Email
	}
	if tokenInfo.Sub != "" {
		credInfo.Subject = tokenInfo.Sub
	}
	credInfo.Scopes = tokenInfo.Scope
	credInfo.ExpiresIn = tokenInfo.ExpiresIn

	return credInfo
}
