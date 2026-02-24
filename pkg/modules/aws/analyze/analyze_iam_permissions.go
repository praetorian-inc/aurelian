package analyze

import (
	"fmt"

	iampkg "github.com/praetorian-inc/aurelian/pkg/aws/iam"
	gaadpkg "github.com/praetorian-inc/aurelian/pkg/aws/iam/gaad"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/cache"
	"github.com/praetorian-inc/aurelian/pkg/model"
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

func (m *AnalyzeIAMPermissionsModule) Run(cfg plugin.Config, emit func(models ...model.AurelianModel)) error {
	c := m.AnalyzeIAMPermissionsConfig

	// Load GAAD data
	gaad, err := iampkg.LoadJSONFile[types.AuthorizationAccountDetails](c.GaadFile)
	if err != nil {
		return fmt.Errorf("loading GAAD file: %w", err)
	}

	// Load optional org policies
	var orgPols *orgpolicies.OrgPolicies
	if c.OrgPoliciesFile != "" {
		op, err := iampkg.LoadJSONFile[orgpolicies.OrgPolicies](c.OrgPoliciesFile)
		if err != nil {
			return fmt.Errorf("loading org policies file: %w", err)
		}
		orgPols = op
	} else {
		orgPols = orgpolicies.NewDefaultOrgPolicies()
	}

	// Load optional resources as cache.Map[output.AWSResource]
	resourceMap := cache.NewMap[output.AWSResource]()
	if c.ResourcesFile != "" {
		r, err := iampkg.LoadJSONFile[[]output.AWSResource](c.ResourcesFile)
		if err != nil {
			return fmt.Errorf("loading resources file: %w", err)
		}
		for _, res := range *r {
			key := res.ARN
			if key == "" {
				key = res.ResourceID
			}
			resourceMap.Set(key, res)
		}
	}

	// Load optional resource policies and attach them to matching resources.
	// If a policy references an ARN not in the resources list, create a
	// minimal AWSResource so the analyzer can still evaluate it.
	if c.ResourcePoliciesFile != "" {
		rp, err := iampkg.LoadJSONFile[map[string]*types.Policy](c.ResourcePoliciesFile)
		if err != nil {
			return fmt.Errorf("loading resource policies file: %w", err)
		}
		attachResourcePolicies(resourceMap, *rp)
	}

	// Analyze IAM permissions
	analyzer := gaadpkg.NewGaadAnalyzer()
	relationships, err := analyzer.Analyze(gaad, orgPols, resourceMap)
	if err != nil {
		return fmt.Errorf("analyzing permissions: %w", err)
	}

	// Convert GAAD entities to AWSIAMResource
	gaadpkg.EmitGAADEntities(gaad, "", func(e output.AWSIAMResource) {
		emit(e)
	})
	relationships.Range(func(_ string, r output.AWSIAMRelationship) bool {
		emit(r)
		return true
	})
	return nil
}

// attachResourcePolicies merges resource policies into the resource map.
// For each ARN in the policy map, if a matching resource exists its
// ResourcePolicy field is set; otherwise a minimal AWSResource is created.
func attachResourcePolicies(resources cache.Map[output.AWSResource], policies map[string]*types.Policy) {
	for resARN, policy := range policies {
		if existing, ok := resources.Get(resARN); ok {
			existing.ResourcePolicy = policy
			resources.Set(resARN, existing)
		} else {
			resources.Set(resARN, output.AWSResource{
				ARN:            resARN,
				ResourcePolicy: policy,
			})
		}
	}
}
