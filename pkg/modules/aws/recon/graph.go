package recon

import (
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/aws/cloudcontrol"
	"github.com/praetorian-inc/aurelian/pkg/aws/gaad"
	iampkg "github.com/praetorian-inc/aurelian/pkg/aws/iam"
	gaadpkg "github.com/praetorian-inc/aurelian/pkg/aws/iam/gaad"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/aws/resourcepolicies"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

//func init() {
//	plugin.Register(&AWSGraphModule{})
//}

type GraphConfig struct {
	plugin.AWSCommonRecon
	plugin.GraphOutputBase
	OrgPoliciesFile string `param:"org-policies-file" desc:"Path to Org Policies JSON file (optional)"`
}

// AWSGraphModule is a refactored version of AWSGraphModule.
type AWSGraphModule struct {
	GraphConfig
}

func (m *AWSGraphModule) ID() string                { return "graph" }
func (m *AWSGraphModule) Name() string              { return "AWS Graph Analysis" }
func (m *AWSGraphModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSGraphModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSGraphModule) OpsecLevel() string        { return "moderate" }
func (m *AWSGraphModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSGraphModule) Description() string {
	return "Collects AWS IAM data (GAAD, resources, policies), evaluates permissions, " +
		"and detects privilege escalation paths. Outputs JSON by default; use --neo4j-uri " +
		"to populate graph database with relationships."
}

func (m *AWSGraphModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html",
	}
}

func (m *AWSGraphModule) SupportedResourceTypes() []string {
	return []string{
		"AWS::Organizations::Account",
	}
}

func (m *AWSGraphModule) Parameters() any {
	return &m.GraphConfig
}

func (m *AWSGraphModule) Run(cfg plugin.Config, emit func(models ...model.AurelianModel)) error {
	c := m.GraphConfig
	resolvedRegions, err := resolveRegions(c.Regions, c.Profile, c.ProfileDir)
	if err != nil {
		return fmt.Errorf("resolving regions: %w", err)
	}
	c.AWSCommonRecon.Regions = resolvedRegions
	policyCollector := resourcepolicies.New(c.AWSCommonRecon)

	// Step 1: Collect GAAD
	gaadData, err := m.collectAccountAuthorizationDetails(c)
	if err != nil {
		return err
	}

	// Step 2+3: Enumerate cloud resources and collect resource policies (streaming)
	resourcesWithPolicies, err := m.collectResourcesWithPolicies(c, policyCollector, resolvedRegions)
	if err != nil {
		return err
	}

	// Step 4: Load org policies
	orgPols, err := m.loadOrgPolicies(c)
	if err != nil {
		return err
	}

	// Step 5: Analyze IAM permissions
	slog.Info("analyzing IAM permissions")
	analyzer := gaadpkg.NewGaadAnalyzer()
	relationships, err := analyzer.Analyze(gaadData, orgPols, resourcesWithPolicies)
	if err != nil {
		return fmt.Errorf("analyzing permissions: %w", err)
	}
	slog.Info("IAM analysis complete", "relationships", len(relationships))

	// Step 6: Build entity list from GAAD + cloud resources
	var iamEntities []output.AWSIAMResource
	for _, user := range gaadData.UserDetailList {
		iamEntities = append(iamEntities, gaadpkg.FromUserDetail(user, gaadData.AccountID))
	}
	for _, role := range gaadData.RoleDetailList {
		iamEntities = append(iamEntities, gaadpkg.FromRoleDetail(role))
	}
	for _, group := range gaadData.GroupDetailList {
		iamEntities = append(iamEntities, gaadpkg.FromGroupDetail(group))
	}
	for _, policy := range gaadData.Policies {
		iamEntities = append(iamEntities, gaadpkg.FromManagedPolicyDetail(policy))
	}

	iamEntities = gaadpkg.DeduplicateByARN(iamEntities)

	for _, e := range iamEntities {
		emit(e)
	}
	for _, r := range resourcesWithPolicies {
		emit(r)
	}
	for _, r := range relationships {
		emit(r)
	}
	return nil
}

func (m *AWSGraphModule) collectAccountAuthorizationDetails(c GraphConfig) (*types.AuthorizationAccountDetails, error) {
	slog.Info("collecting account authorization details")
	g := gaad.New(c.AWSReconBase)
	gaadData, err := g.Get()
	if err != nil {
		return nil, fmt.Errorf("collecting GAAD: %w", err)
	}
	slog.Info("GAAD collected",
		"account", gaadData.AccountID,
		"users", len(gaadData.UserDetailList),
		"roles", len(gaadData.RoleDetailList),
		"groups", len(gaadData.GroupDetailList))
	return gaadData, nil
}

func (m *AWSGraphModule) collectResourcesWithPolicies(c GraphConfig, collector *resourcepolicies.ResourcePolicyCollector, resolvedRegions []string) ([]output.AWSResource, error) {
	slog.Info("enumerating cloud resources and collecting policies",
		"types", len(collector.SupportedResourceTypes()), "regions", len(resolvedRegions))

	lister := cloudcontrol.NewCloudControlLister(c.AWSCommonRecon)

	p1 := pipeline.From(collector.SupportedResourceTypes()...)
	p2 := pipeline.New[output.AWSResource]()
	p3 := pipeline.New[output.AWSResource]()
	pipeline.Pipe(p1, lister.List, p2)
	pipeline.Pipe(p2, collector.Collect, p3)

	var results []output.AWSResource
	for r := range p3.Range() {
		results = append(results, r)
	}
	if err := p3.Wait(); err != nil {
		return nil, fmt.Errorf("collecting resources with policies: %w", err)
	}

	slog.Info("resources with policies collected", "count", len(results))
	return results, nil
}

func (m *AWSGraphModule) loadOrgPolicies(c GraphConfig) (*orgpolicies.OrgPolicies, error) {
	if c.OrgPoliciesFile != "" {
		slog.Info("loading org policies", "file", c.OrgPoliciesFile)
		op, err := iampkg.LoadJSONFile[orgpolicies.OrgPolicies](c.OrgPoliciesFile)
		if err != nil {
			return nil, fmt.Errorf("loading org policies: %w", err)
		}
		return op, nil
	}
	return orgpolicies.NewDefaultOrgPolicies(), nil
}
