package recon

import (
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/aws/cloudcontrol"
	"github.com/praetorian-inc/aurelian/pkg/aws/gaad"
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
	policyCollector := resourcepolicies.New(c.Profile, c.ProfileDir)

	gaadData, err := m.collectAccountAuthorizationDetails(c)
	if err != nil {
		return nil, err
	}
	_ = gaadData

	resourcesByRegion, err := m.collectResources(c, policyCollector)
	if err != nil {
		return nil, err
	}

	resourcesWithPolicies, err := m.collectResourcePolicies(policyCollector, resourcesByRegion)
	if err != nil {
		return nil, err
	}
	_ = resourcesWithPolicies

	return nil, nil
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
