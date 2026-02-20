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
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	plugin.Register(&AWSGraphNewModule{})
}

// AWSGraphNewModule is a refactored version of AWSGraphModule.
type AWSGraphNewModule struct {
	GraphConfig
}

func (m *AWSGraphNewModule) ID() string                { return "graph-new" }
func (m *AWSGraphNewModule) Name() string              { return "AWS Graph Analysis" }
func (m *AWSGraphNewModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSGraphNewModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSGraphNewModule) OpsecLevel() string        { return "moderate" }
func (m *AWSGraphNewModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSGraphNewModule) Description() string {
	return "Collects AWS IAM data (GAAD, resources, policies), evaluates permissions, " +
		"and detects privilege escalation paths. Outputs JSON by default; use --neo4j-uri " +
		"to populate graph database with relationships."
}

func (m *AWSGraphNewModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html",
	}
}

func (m *AWSGraphNewModule) SupportedResourceTypes() []string {
	return []string{
		"AWS::Organizations::Account",
	}
}

func (m *AWSGraphNewModule) Parameters() any {
	return &m.GraphConfig
}

func (m *AWSGraphNewModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	c := m.GraphConfig
	policyCollector := resourcepolicies.New(c.AWSCommonRecon)

	// Step 1: Collect GAAD
	gaadData, err := m.collectAccountAuthorizationDetails(c)
	if err != nil {
		return nil, err
	}

	// Step 2: Enumerate cloud resources
	resourcesByRegion, err := m.collectResources(c, policyCollector)
	if err != nil {
		return nil, err
	}

	// Step 3: Collect resource policies
	resourcesWithPolicies, err := m.collectResourcePolicies(policyCollector, resourcesByRegion)
	if err != nil {
		return nil, err
	}

	// Step 4: Load org policies
	orgPols, err := m.loadOrgPolicies(c)
	if err != nil {
		return nil, err
	}

	// Step 5: Analyze IAM permissions
	slog.Info("analyzing IAM permissions")
	analyzer := gaadpkg.NewGaadAnalyzer()
	relationships, err := analyzer.Analyze(gaadData, orgPols, resourcesWithPolicies)
	if err != nil {
		return nil, fmt.Errorf("analyzing permissions: %w", err)
	}
	slog.Info("IAM analysis complete", "relationships", len(relationships))

	// Step 6: Build entity list from GAAD + cloud resources
	var entities []output.AWSIAMResource
	for _, user := range gaadData.UserDetailList {
		entities = append(entities, iampkg.FromUserDL(user, gaadData.AccountID))
	}
	for _, role := range gaadData.RoleDetailList {
		entities = append(entities, iampkg.FromRoleDL(role))
	}
	for _, group := range gaadData.GroupDetailList {
		entities = append(entities, iampkg.FromGroupDL(group))
	}
	for _, policy := range gaadData.Policies {
		entities = append(entities, iampkg.FromPolicyDL(policy))
	}

	// Flatten all cloud resources (not just those with policies)
	for _, regionResources := range resourcesByRegion {
		for _, cr := range regionResources {
			entities = append(entities, output.FromAWSResource(cr))
		}
	}
	entities = iampkg.DeduplicateByARN(entities)

	return []plugin.Result{
		{
			Data: entities,
			Metadata: map[string]any{
				"module":    m.ID(),
				"type":      "entities",
				"accountID": gaadData.AccountID,
				"count":     len(entities),
			},
		},
		{
			Data: relationships,
			Metadata: map[string]any{
				"module": m.ID(),
				"type":   "iam_relationships",
				"count":  len(relationships),
			},
		},
	}, nil
}

func (m *AWSGraphNewModule) collectAccountAuthorizationDetails(c GraphConfig) (*types.AuthorizationAccountDetails, error) {
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

func (m *AWSGraphNewModule) collectResources(c GraphConfig, policyCollector *resourcepolicies.ResourcePolicyCollector) (map[string][]output.AWSResource, error) {
	resolvedRegions, err := resolveRegions(c.Regions, c.Profile, c.ProfileDir)
	if err != nil {
		return nil, fmt.Errorf("resolving regions: %w", err)
	}
	slog.Info("resolved regions", "regions", resolvedRegions)

	lister := cloudcontrol.NewCloudControlLister(c.AWSCommonRecon)
	resourceTypesToScan := policyCollector.SupportedResourceTypes()

	slog.Info("enumerating cloud resources", "types", len(resourceTypesToScan), "regions", len(resolvedRegions))
	allResources, err := lister.List(resolvedRegions, resourceTypesToScan)
	if err != nil {
		return nil, fmt.Errorf("listing resources: %w", err)
	}

	// Re-key by region (CloudControl returns keys as "region/type")
	total := 0
	byRegion := make(map[string][]output.AWSResource)
	for _, resources := range allResources {
		for _, r := range resources {
			byRegion[r.Region] = append(byRegion[r.Region], r)
		}
		total += len(resources)
	}

	slog.Info("resources enumerated", "count", total, "regions", len(byRegion))
	return byRegion, nil
}

func (m *AWSGraphNewModule) collectResourcePolicies(policyCollector *resourcepolicies.ResourcePolicyCollector, resourcesByRegion map[string][]output.AWSResource) ([]output.AWSResource, error) {
	slog.Info("collecting resource policies")
	resourcesWithPolicies, err := policyCollector.Collect(resourcesByRegion)
	if err != nil {
		return nil, fmt.Errorf("collecting resource policies: %w", err)
	}
	slog.Info("resource policies collected", "count", len(resourcesWithPolicies))
	return resourcesWithPolicies, nil
}

func (m *AWSGraphNewModule) loadOrgPolicies(c GraphConfig) (*orgpolicies.OrgPolicies, error) {
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
