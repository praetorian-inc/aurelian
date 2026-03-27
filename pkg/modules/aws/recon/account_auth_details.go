package recon

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/praetorian-inc/aurelian/pkg/aws/gaad"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AWSAccountAuthDetailsModule{})
}

// AccountAuthDetailsConfig holds the typed parameters for account-auth-details module.
type AccountAuthDetailsConfig struct {
	OutputDir  string   `param:"output-dir"   desc:"Base output directory" default:"aurelian-output"`
	Profile    string   `param:"profile"      desc:"AWS profile to use"`
	ProfileDir string   `param:"profile-dir"  desc:"Set to override the default AWS profile directory"`
	Profiles   []string `param:"profiles"     desc:"AWS profiles to collect (comma-separated)" shortcode:"p"`
}

// AWSAccountAuthDetailsModule retrieves IAM account authorization details
type AWSAccountAuthDetailsModule struct {
	AccountAuthDetailsConfig
}

func (m *AWSAccountAuthDetailsModule) ID() string                { return "account-auth-details" }
func (m *AWSAccountAuthDetailsModule) Name() string              { return "AWS Get Account Authorization Details" }
func (m *AWSAccountAuthDetailsModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSAccountAuthDetailsModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSAccountAuthDetailsModule) OpsecLevel() string        { return "moderate" }
func (m *AWSAccountAuthDetailsModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSAccountAuthDetailsModule) Description() string {
	return "Retrieves IAM account authorization details including users, roles, groups, and policies. " +
		"Supports multiple profiles for multi-account collection. " +
		"IAM is a global service, so this module always queries us-east-1 region."
}

func (m *AWSAccountAuthDetailsModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html",
	}
}

func (m *AWSAccountAuthDetailsModule) SupportedResourceTypes() []string {
	return []string{
		"AWS::IAM::User",
		"AWS::IAM::Role",
		"AWS::IAM::Group",
		"AWS::IAM::Policy",
	}
}

func (m *AWSAccountAuthDetailsModule) Parameters() any {
	return &m.AccountAuthDetailsConfig
}

func (m *AWSAccountAuthDetailsModule) resolveProfiles() []string {
	if len(m.Profiles) > 0 {
		return m.Profiles
	}
	return []string{m.Profile}
}

func (m *AWSAccountAuthDetailsModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	profiles := m.resolveProfiles()

	type result struct {
		profile   string
		accountID string
		data      any
		err       error
	}

	results := make([]result, len(profiles))
	var wg sync.WaitGroup
	for i, profile := range profiles {
		wg.Add(1)
		go func(idx int, p string) {
			defer wg.Done()
			opts := plugin.AWSReconBase{
				OutputDir:  m.OutputDir,
				Profile:    p,
				ProfileDir: m.ProfileDir,
			}
			g := gaad.New(opts)
			data, err := g.Get()
			if err != nil {
				results[idx] = result{profile: p, err: err}
				return
			}
			results[idx] = result{profile: p, accountID: data.AccountID, data: data}
			cfg.Log.Success("GAAD collected for profile %q (account: %s)", p, data.AccountID)
		}(i, profile)
	}
	wg.Wait()

	gaadDir := filepath.Join(m.OutputDir, "gaad")

	var errs []error
	for _, r := range results {
		if r.err != nil {
			errs = append(errs, fmt.Errorf("profile %q: %w", r.profile, r.err))
			continue
		}

		// Send through pipeline for framework output.
		out.Send(r.data.(model.AurelianModel))

		// Write individual GAAD file.
		path := filepath.Join(gaadDir, r.accountID+".json")
		if err := os.MkdirAll(gaadDir, 0o755); err != nil {
			return fmt.Errorf("creating gaad dir: %w", err)
		}
		data, err := json.MarshalIndent(r.data, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling GAAD for %s: %w", r.accountID, err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return fmt.Errorf("writing GAAD for %s: %w", r.accountID, err)
		}
		cfg.Log.Success("GAAD written to %s", path)
	}

	if len(errs) == len(profiles) {
		return fmt.Errorf("all profiles failed: %v", errs)
	}

	return nil
}
