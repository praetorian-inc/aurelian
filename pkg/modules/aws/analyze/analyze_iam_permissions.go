package analyze

import (
	"fmt"

	iampkg "github.com/praetorian-inc/aurelian/pkg/aws/iam"
	gaadpkg "github.com/praetorian-inc/aurelian/pkg/aws/iam/gaad"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/output"
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
	AnalyzeIAMPermissionsConfig
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
	return &m.AnalyzeIAMPermissionsConfig
}

func (m *AnalyzeIAMPermissionsModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	c := m.AnalyzeIAMPermissionsConfig

	// Load GAAD data
	gaad, err := iampkg.LoadJSONFile[types.AuthorizationAccountDetails](c.GaadFile)
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

	// Load optional resources as []output.AWSResource
	var resources []output.AWSResource
	if c.ResourcesFile != "" {
		r, err := iampkg.LoadJSONFile[[]output.AWSResource](c.ResourcesFile)
		if err != nil {
			return nil, fmt.Errorf("loading resources file: %w", err)
		}
		resources = *r
	}

	// Load optional resource policies and attach them to matching resources.
	// If a policy references an ARN not in the resources list, create a
	// minimal AWSResource so the analyzer can still evaluate it.
	if c.ResourcePoliciesFile != "" {
		rp, err := iampkg.LoadJSONFile[map[string]*types.Policy](c.ResourcePoliciesFile)
		if err != nil {
			return nil, fmt.Errorf("loading resource policies file: %w", err)
		}
		resources = attachResourcePolicies(resources, *rp)
	}

	// Analyze IAM permissions
	analyzer := gaadpkg.NewGaadAnalyzer()
	relationships, err := analyzer.Analyze(gaad, orgPols, resources)
	if err != nil {
		return nil, fmt.Errorf("analyzing permissions: %w", err)
	}

	// Convert GAAD entities to AWSIAMResource
	entities := iampkg.FromGAAD(gaad, "")

	return []plugin.Result{
		{
			Data: entities,
			Metadata: map[string]any{
				"module":   m.ID(),
				"platform": m.Platform(),
				"type":     "entities",
				"count":    len(entities),
			},
		},
		{
			Data: relationships,
			Metadata: map[string]any{
				"module":   m.ID(),
				"platform": m.Platform(),
				"type":     "iam_relationships",
				"count":    len(relationships),
			},
		},
	}, nil
}

// attachResourcePolicies merges resource policies into the resource list.
// For each ARN in the policy map, if a matching resource exists its
// ResourcePolicy field is set; otherwise a minimal AWSResource is created.
func attachResourcePolicies(resources []output.AWSResource, policies map[string]*types.Policy) []output.AWSResource {
	byARN := make(map[string]int, len(resources))
	for i := range resources {
		byARN[resources[i].ARN] = i
	}

	for arn, policy := range policies {
		if idx, ok := byARN[arn]; ok {
			resources[idx].ResourcePolicy = policy
		} else {
			resources = append(resources, output.AWSResource{
				ARN:            arn,
				ResourcePolicy: policy,
			})
		}
	}

	return resources
}
