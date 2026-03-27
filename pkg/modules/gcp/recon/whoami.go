package recon

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

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
	plugin.GCPCommonRecon
}

type GCPWhoamiModule struct {
	GCPWhoamiConfig
}

func (m *GCPWhoamiModule) ID() string                  { return "whoami" }
func (m *GCPWhoamiModule) Name() string                { return "GCP Covert Whoami" }
func (m *GCPWhoamiModule) Platform() plugin.Platform   { return plugin.PlatformGCP }
func (m *GCPWhoamiModule) Category() plugin.Category   { return plugin.CategoryRecon }
func (m *GCPWhoamiModule) OpsecLevel() string          { return "stealth" }
func (m *GCPWhoamiModule) Authors() []string           { return []string{"Praetorian"} }
func (m *GCPWhoamiModule) SupportedResourceTypes() []string { return nil }
func (m *GCPWhoamiModule) Parameters() any             { return &m.GCPWhoamiConfig }

func (m *GCPWhoamiModule) Description() string {
	return "Determine caller identity via the OAuth2 tokeninfo endpoint without generating GCP Cloud Audit Logs."
}

func (m *GCPWhoamiModule) References() []string {
	return []string{"https://cloud.google.com/docs/authentication/token-types"}
}

func (m *GCPWhoamiModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	ctx := cfg.Context
	creds, err := google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return fmt.Errorf("whoami: find credentials: %w", err)
	}
	token, err := creds.TokenSource.Token()
	if err != nil {
		return fmt.Errorf("whoami: get token: %w", err)
	}

	url := "https://oauth2.googleapis.com/tokeninfo?access_token=" + token.AccessToken
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("whoami: create request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("whoami: tokeninfo request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var info struct {
		Email     string `json:"email"`
		Sub       string `json:"sub"`
		Scope     string `json:"scope"`
		ExpiresIn string `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		cfg.Warn("tokeninfo returned non-JSON response")
		out.Send(&output.GCPCallerIdentity{Status: "error"})
		return nil
	}

	cfg.Success("identity: %s (sub: %s)", info.Email, info.Sub)
	out.Send(&output.GCPCallerIdentity{
		Status:    "success",
		Email:     info.Email,
		Subject:   info.Sub,
		Scopes:    info.Scope,
		ExpiresIn: info.ExpiresIn,
	})
	return nil
}
