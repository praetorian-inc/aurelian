package analyze

import (
	"fmt"

	iampkg "github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	plugin.Register(&AnalyzeIAMPermissionsModule{})
}

type AnalyzeIAMPermissionsConfig struct {
	GaadFile             string `param:"gaad-file"              desc:"Path to GAAD JSON file (from account-auth-details module)" required:"true"`
	OrgPoliciesFile      string `param:"org-policies-file"      desc:"Path to Org Policies JSON file (from org-policies module)"`
	ResourcePoliciesFile string `param:"resource-policies-file" desc:"Path to Resource Policies JSON file"`
	ResourcesFile        string `param:"resources-file"         desc:"Path to Resources JSON file (from list-all module)"`
}

type AnalyzeIAMPermissionsModule struct {
	config AnalyzeIAMPermissionsConfig
}

func (m *AnalyzeIAMPermissionsModule) ID() string                { return "analyze-iam-permissions" }
func (m *AnalyzeIAMPermissionsModule) Name() string              { return "AWS Analyze IAM Permissions" }
func (m *AnalyzeIAMPermissionsModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AnalyzeIAMPermissionsModule) Category() plugin.Category { return plugin.CategoryAnalyze }
func (m *AnalyzeIAMPermissionsModule) OpsecLevel() string        { return "none" }
func (m *AnalyzeIAMPermissionsModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AnalyzeIAMPermissionsModule) Description() string {
	return "Analyzes IAM permissions from GAAD data to detect privilege escalation paths, " +
		"cross-account access, and create-then-use attack patterns. Requires GAAD JSON file from account-auth-details module."
}

func (m *AnalyzeIAMPermissionsModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_understand-policy-summary.html",
	}
}

func (m *AnalyzeIAMPermissionsModule) SupportedResourceTypes() []string {
	return []string{
		"AWS::IAM::User",
		"AWS::IAM::Role",
		"AWS::IAM::Group",
		"AWS::IAM::Policy",
	}
}

func (m *AnalyzeIAMPermissionsModule) Parameters() any {
	return &m.config
}

func (m *AnalyzeIAMPermissionsModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	c := m.config

	// Load GAAD data
	gaad, err := iampkg.LoadJSONFile[iampkg.Gaad](c.GaadFile)
	if err != nil {
		return nil, fmt.Errorf("loading GAAD file: %w", err)
	}

	// Load optional org policies
	var orgPols *orgpolicies.OrgPolicies
	if c.OrgPoliciesFile != "" {
		op, err := iampkg.LoadJSONFile[orgpolicies.OrgPolicies](c.OrgPoliciesFile)
		if err != nil {
			return nil, fmt.Errorf("loading org policies file: %w", err)
		}
		orgPols = op
	} else {
		orgPols = orgpolicies.NewDefaultOrgPolicies()
	}

	// Load optional resource policies
	var resourcePolicies map[string]*types.Policy
	if c.ResourcePoliciesFile != "" {
		rp, err := iampkg.LoadJSONFile[map[string]*types.Policy](c.ResourcePoliciesFile)
		if err != nil {
			return nil, fmt.Errorf("loading resource policies file: %w", err)
		}
		resourcePolicies = *rp
	}

	// Load optional resources
	var resources *[]types.EnrichedResourceDescription
	if c.ResourcesFile != "" {
		r, err := iampkg.LoadJSONFile[[]types.EnrichedResourceDescription](c.ResourcesFile)
		if err != nil {
			return nil, fmt.Errorf("loading resources file: %w", err)
		}
		resources = r
	}

	// Create PolicyData and analyzer
	pd := iampkg.NewPolicyData(gaad, orgPols, resourcePolicies, resources)
	analyzer := iampkg.NewGaadAnalyzer(pd)

	// Run analysis
	summary, err := analyzer.AnalyzePrincipalPermissions()
	if err != nil {
		return nil, fmt.Errorf("analyzing permissions: %w", err)
	}

	results := analyzer.FullResults(summary)

	return []plugin.Result{
		{
			Data: results,
			Metadata: map[string]any{
				"module":   m.ID(),
				"platform": m.Platform(),
				"count":    len(results),
			},
		},
	}, nil
}
