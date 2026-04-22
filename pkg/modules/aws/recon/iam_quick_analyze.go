package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/praetorian-inc/aurelian/pkg/aws/gaad"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/aws/iamquick"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/store"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	plugin.Register(&AWSIAMQuickAnalyzeModule{})
}

// IAMQuickAnalyzeConfig holds parameters for the iam-quick-analyze module.
type IAMQuickAnalyzeConfig struct {
	OutputDir  string   `param:"output-dir"   desc:"Base output directory" default:"aurelian-output"`
	ProfileDir string   `param:"profile-dir"  desc:"Set to override the default AWS profile directory"`
	Profiles   []string `param:"profiles"     desc:"AWS profiles to analyze (comma-separated)" shortcode:"p"`
	GAADDir    string   `param:"gaad-dir"     desc:"Directory of pre-collected GAAD JSON files (skips live collection)" shortcode:"D"`
}

// AWSIAMQuickAnalyzeModule scans GAAD data for privilege escalation paths
// and trust relationship misconfigurations without requiring a full graph build.
type AWSIAMQuickAnalyzeModule struct {
	IAMQuickAnalyzeConfig
}

func (m *AWSIAMQuickAnalyzeModule) ID() string   { return "iam-quick-analyze" }
func (m *AWSIAMQuickAnalyzeModule) Name() string { return "AWS IAM Quick Analyze" }
func (m *AWSIAMQuickAnalyzeModule) Description() string {
	return "Quick IAM analysis: collects GAAD from one or more AWS profiles, scans for privilege " +
		"escalation paths and trust relationship issues. " +
		"Faster than the full graph module — no resource enumeration or Neo4j required."
}
func (m *AWSIAMQuickAnalyzeModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSIAMQuickAnalyzeModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSIAMQuickAnalyzeModule) OpsecLevel() string        { return "moderate" }
func (m *AWSIAMQuickAnalyzeModule) Authors() []string         { return []string{"Praetorian"} }
func (m *AWSIAMQuickAnalyzeModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html",
	}
}
func (m *AWSIAMQuickAnalyzeModule) SupportedResourceTypes() []string {
	return []string{"AWS::Organizations::Account"}
}
func (m *AWSIAMQuickAnalyzeModule) Parameters() any { return &m.IAMQuickAnalyzeConfig }

func (m *AWSIAMQuickAnalyzeModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	var combined *types.AuthorizationAccountDetails
	var accountIDs []string
	var err error

	if m.GAADDir != "" {
		// Local mode: load from pre-collected GAAD files.
		combined, accountIDs, err = m.loadGAADsFromDir(cfg)
	} else {
		// Live mode: collect from AWS profiles.
		combined, accountIDs, err = m.collectGAADs(cfg)
	}
	if err != nil {
		return err
	}

	// IAM analysis.
	analyzer := iamquick.NewAnalyzer(combined)
	findings := analyzer.Collect()

	// Org policies + hierarchy — only in live mode (requires AWS credentials).
	var orgData *orgpolicies.OrgPolicies
	var hierarchy *orgpolicies.OrgUnit
	if m.GAADDir == "" && len(m.Profiles) > 0 {
		orgData, hierarchy, err = m.collectOrg(cfg)
		if err != nil {
			cfg.Log.Warn("org policy collection failed (profile may lack organizations:List* permissions): %v", err)
		}
	}

	// Write structured output.
	base := filepath.Join(m.OutputDir, "iam-quick-analyze")
	if err := m.writeFindings(base, findings); err != nil {
		return fmt.Errorf("writing findings: %w", err)
	}
	if orgData != nil {
		if err := m.writeOrgData(base, orgData, hierarchy, accountIDs); err != nil {
			return fmt.Errorf("writing org data: %w", err)
		}
	}

	// Log summary.
	cfg.Log.Success("wrote %d privesc files, %d trust files to %s",
		len(findings.Privesc), len(findings.Trusts), base)
	if orgData != nil {
		cfg.Log.Success("wrote org hierarchy and SCP mappings for %d accounts", len(accountIDs))
	}

	return nil
}

// loadGAADsFromDir reads all JSON files from the gaad-dir, parses them as
// AuthorizationAccountDetails, and merges them.
func (m *AWSIAMQuickAnalyzeModule) loadGAADsFromDir(cfg plugin.Config) (*types.AuthorizationAccountDetails, []string, error) {
	entries, err := os.ReadDir(m.GAADDir)
	if err != nil {
		return nil, nil, fmt.Errorf("reading gaad-dir %q: %w", m.GAADDir, err)
	}

	combined := &types.AuthorizationAccountDetails{
		AccountID: "multi-account",
		Users:     store.NewMap[types.UserDetail](),
		Groups:    store.NewMap[types.GroupDetail](),
		Roles:     store.NewMap[types.RoleDetail](),
		Policies:  store.NewMap[types.ManagedPolicyDetail](),
	}

	var accountIDs []string
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(m.GAADDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("reading %s: %w", path, err)
		}

		var gaadData types.AuthorizationAccountDetails
		if err := json.Unmarshal(data, &gaadData); err != nil {
			return nil, nil, fmt.Errorf("parsing %s: %w", path, err)
		}

		accountIDs = append(accountIDs, gaadData.AccountID)
		cfg.Log.Success("loaded GAAD from %s (account: %s)", entry.Name(), gaadData.AccountID)

		gaadData.Users.Range(func(arn string, u types.UserDetail) bool { combined.Users.Set(arn, u); return true })
		gaadData.Groups.Range(func(arn string, g types.GroupDetail) bool { combined.Groups.Set(arn, g); return true })
		gaadData.Roles.Range(func(arn string, r types.RoleDetail) bool { combined.Roles.Set(arn, r); return true })
		gaadData.Policies.Range(func(arn string, p types.ManagedPolicyDetail) bool { combined.Policies.Set(arn, p); return true })
	}

	if len(accountIDs) == 0 {
		return nil, nil, fmt.Errorf("no valid GAAD JSON files found in %s", m.GAADDir)
	}

	return combined, accountIDs, nil
}

// collectOrg collects organization hierarchy and policies using the first profile.
func (m *AWSIAMQuickAnalyzeModule) collectOrg(cfg plugin.Config) (*orgpolicies.OrgPolicies, *orgpolicies.OrgUnit, error) {
	if len(m.Profiles) == 0 {
		return nil, nil, fmt.Errorf("no profiles configured")
	}
	opts := orgpolicies.CollectorOptions{
		Profile:    m.Profiles[0],
		ProfileDir: m.ProfileDir,
	}
	orgData, err := orgpolicies.CollectOrgPolicies(context.Background(), opts)
	if err != nil {
		return nil, nil, err
	}

	// Re-collect hierarchy separately for the raw tree output.
	// The hierarchy is embedded in orgData.Targets but not as a tree.
	// Use a lightweight approach: extract from the collector directly.
	hierarchyOpts := orgpolicies.CollectorOptions{
		Profile:    m.Profiles[0],
		ProfileDir: m.ProfileDir,
	}
	_ = hierarchyOpts // hierarchy comes from the same collection
	// The OrgUnit tree isn't exposed from CollectOrgPolicies, so we re-collect it.
	hierarchy, err := orgpolicies.CollectOrgHierarchy(context.Background(), opts)
	if err != nil {
		return orgData, nil, nil // org data without hierarchy is still useful
	}
	return orgData, hierarchy, nil
}

func (m *AWSIAMQuickAnalyzeModule) writeFindings(base string, f *iamquick.Findings) error {
	for name, items := range f.Privesc {
		if err := writeJSON(filepath.Join(base, "privesc", name+".json"), items); err != nil {
			return err
		}
	}
	for name, items := range f.Trusts {
		if err := writeJSON(filepath.Join(base, "trusts", name+".json"), items); err != nil {
			return err
		}
	}
	return nil
}

func (m *AWSIAMQuickAnalyzeModule) writeOrgData(
	base string,
	orgData *orgpolicies.OrgPolicies,
	hierarchy *orgpolicies.OrgUnit,
	accountIDs []string,
) error {
	// scps.json: account ID → all applicable SCP statements (direct + inherited).
	scpMap := make(map[string][]scpEntry)
	for _, acctID := range accountIDs {
		target := orgData.GetPolicyForTarget(acctID)
		if target == nil {
			continue
		}
		var entries []scpEntry
		// Direct policies.
		for _, arn := range target.SCPs.DirectPolicies {
			pol := orgData.GetPolicyContent(arn, "scps")
			if pol == nil {
				continue
			}
			entries = append(entries, scpEntry{
				PolicyARN: arn,
				AppliedAt: "direct",
				Policy:    *pol,
			})
		}
		// Inherited from parent OUs/root.
		for _, parent := range target.SCPs.ParentPolicies {
			for _, arn := range parent.Policies {
				pol := orgData.GetPolicyContent(arn, "scps")
				if pol == nil {
					continue
				}
				entries = append(entries, scpEntry{
					PolicyARN: arn,
					AppliedAt: fmt.Sprintf("inherited:%s (%s)", parent.Name, parent.ID),
					Policy:    *pol,
				})
			}
		}
		if len(entries) > 0 {
			scpMap[acctID] = entries
		}
	}
	if err := writeJSON(filepath.Join(base, "org", "scps.json"), scpMap); err != nil {
		return err
	}

	// hierarchy.json: the org tree.
	if hierarchy != nil {
		if err := writeJSON(filepath.Join(base, "org", "hierarchy.json"), hierarchy); err != nil {
			return err
		}
	}

	return nil
}

type scpEntry struct {
	PolicyARN string       `json:"policy_arn"`
	AppliedAt string       `json:"applied_at"`
	Policy    types.Policy `json:"policy"`
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}


// collectGAADs collects GAAD data from each profile in parallel
// and merges them into a single AuthorizationAccountDetails (deduplicated by ARN).
func (m *AWSIAMQuickAnalyzeModule) collectGAADs(cfg plugin.Config) (*types.AuthorizationAccountDetails, []string, error) {
	type result struct {
		data *types.AuthorizationAccountDetails
		err  error
	}

	results := make([]result, len(m.Profiles))
	var wg sync.WaitGroup
	for i, profile := range m.Profiles {
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
			results[idx] = result{data: data, err: err}
			if err == nil {
				cfg.Log.Success("GAAD collected for profile %q (account: %s)", p, data.AccountID)
			}
		}(i, profile)
	}
	wg.Wait()

	combined := &types.AuthorizationAccountDetails{
		AccountID: "multi-account",
		Users:     store.NewMap[types.UserDetail](),
		Groups:    store.NewMap[types.GroupDetail](),
		Roles:     store.NewMap[types.RoleDetail](),
		Policies:  store.NewMap[types.ManagedPolicyDetail](),
	}

	var errs []error
	var accountIDs []string
	for i, r := range results {
		if r.err != nil {
			errs = append(errs, fmt.Errorf("profile %q: %w", m.Profiles[i], r.err))
			continue
		}
		accountIDs = append(accountIDs, r.data.AccountID)
		r.data.Users.Range(func(arn string, u types.UserDetail) bool {
			combined.Users.Set(arn, u)
			return true
		})
		r.data.Groups.Range(func(arn string, g types.GroupDetail) bool {
			combined.Groups.Set(arn, g)
			return true
		})
		r.data.Roles.Range(func(arn string, role types.RoleDetail) bool {
			combined.Roles.Set(arn, role)
			return true
		})
		r.data.Policies.Range(func(arn string, p types.ManagedPolicyDetail) bool {
			combined.Policies.Set(arn, p)
			return true
		})
	}

	if len(errs) == len(m.Profiles) {
		return nil, nil, fmt.Errorf("all profiles failed: %v", errs)
	}

	return combined, accountIDs, nil
}
