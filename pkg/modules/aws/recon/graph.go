package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/aws/cloudcontrol"
	"github.com/praetorian-inc/aurelian/pkg/aws/gaad"
	iampkg "github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/aws/resourcepolicies"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	plugin.Register(&AWSGraphModule{})
}

// GraphConfig holds parameters for the graph module
type GraphConfig struct {
	plugin.AWSCommonRecon
	plugin.GraphOutputBase
	OrgPoliciesFile string `param:"org-policies-file" desc:"Path to Org Policies JSON file (optional)"`
}

// AWSGraphModule collects AWS IAM data and evaluates permissions for graph analysis
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

func (m *AWSGraphModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	c := m.GraphConfig

	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	// Step 1: Collect GAAD
	slog.Info("collecting account authorization details")
	gaadData, accountID, err := gaad.GetAccountAuthorizationDetails(ctx, c.AWSReconBase)
	if err != nil {
		return nil, fmt.Errorf("collecting GAAD: %w", err)
	}
	slog.Info("GAAD collected",
		"account", accountID,
		"users", len(gaadData.UserDetailList),
		"roles", len(gaadData.RoleDetailList),
		"groups", len(gaadData.GroupDetailList))

	// Step 2: Resolve regions
	resolvedRegions, err := graphResolveRegions(c.Regions, c.Profile, c.ProfileDir)
	if err != nil {
		return nil, fmt.Errorf("resolving regions: %w", err)
	}
	slog.Info("resolved regions", "regions", resolvedRegions)

	// Step 3: Enumerate CloudControl resources
	lister := cloudcontrol.NewCloudControlLister(c.AWSCommonRecon)
	resourceTypesToScan := resourcepolicies.SupportedResourceTypes()

	slog.Info("enumerating cloud resources", "types", len(resourceTypesToScan), "regions", len(resolvedRegions))
	allResources, err := lister.List(resolvedRegions, resourceTypesToScan)
	if err != nil {
		return nil, fmt.Errorf("listing resources: %w", err)
	}

	// Flatten resource map
	var resourcesList []output.CloudResource
	for _, resources := range allResources {
		resourcesList = append(resourcesList, resources...)
	}
	slog.Info("resources enumerated", "count", len(resourcesList))

	// Step 4: Collect resource policies per region
	var resourcesWithPolicies []output.CloudResource
	for _, region := range resolvedRegions {
		var regionResources []output.CloudResource
		for _, resource := range resourcesList {
			if resource.Region == region {
				regionResources = append(regionResources, resource)
			}
		}
		if len(regionResources) == 0 {
			continue
		}

		awsCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
			Region:     region,
			Profile:    c.Profile,
			ProfileDir: c.ProfileDir,
		})
		if err != nil {
			return nil, fmt.Errorf("creating AWS config for %s: %w", region, err)
		}

		regionPolicied, err := resourcepolicies.CollectPolicies(ctx, awsCfg, regionResources)
		if err != nil {
			slog.Warn("collecting policies failed", "region", region, "error", err)
			continue // Non-fatal: continue with other regions
		}
		resourcesWithPolicies = append(resourcesWithPolicies, regionPolicied...)
	}
	slog.Info("resource policies collected", "count", len(resourcesWithPolicies))

	// Step 5: Build EnrichedResourceDescriptions for IAM analysis
	var enrichedResources []types.EnrichedResourceDescription
	for _, cr := range resourcesWithPolicies {
		erd := types.NewEnrichedResourceDescription(
			cr.ResourceID,
			cr.ResourceType,
			cr.Region,
			cr.AccountRef,
			cr.Properties,
		)
		enrichedResources = append(enrichedResources, erd)
	}

	// Step 6: Load optional org policies
	var orgPols *orgpolicies.OrgPolicies
	if c.OrgPoliciesFile != "" {
		op, err := iampkg.LoadJSONFile[orgpolicies.OrgPolicies](c.OrgPoliciesFile)
		if err != nil {
			return nil, fmt.Errorf("loading org policies: %w", err)
		}
		orgPols = op
	} else {
		orgPols = orgpolicies.NewDefaultOrgPolicies()
	}

	// Step 7: Extract resource policies map
	resourcePoliciesMap := make(map[string]*types.Policy)
	for _, resource := range resourcesWithPolicies {
		if policyData, ok := resource.Properties["ResourcePolicy"]; ok {
			if policyJSON, ok := policyData.(string); ok {
				var policy types.Policy
				if err := json.Unmarshal([]byte(policyJSON), &policy); err == nil {
					resourcePoliciesMap[resource.ARN] = &policy
				}
			}
		}
	}

	// Step 8: Run IAM permission analysis
	slog.Info("analyzing IAM permissions")
	pd := iampkg.NewPolicyData(gaadData, orgPols, resourcePoliciesMap, &enrichedResources)
	analyzer := iampkg.NewGaadAnalyzer(pd)

	summary, err := analyzer.AnalyzePrincipalPermissions()
	if err != nil {
		return nil, fmt.Errorf("analyzing permissions: %w", err)
	}

	fullResults := analyzer.FullResults(summary)
	slog.Info("IAM analysis complete", "relationships", len(fullResults))

	// Convert GAAD entities to AWSIAMResource (GAAD first so they win dedup)
	var entities []output.AWSIAMResource
	for _, user := range gaadData.UserDetailList {
		entities = append(entities, iampkg.FromUserDL(user, accountID))
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

	// Convert cloud resources to AWSIAMResource (IAM fields nil)
	for _, cr := range resourcesList {
		entities = append(entities, output.FromCloudResource(cr))
	}

	// Deduplicate: GAAD version wins (has typed IAM fields)
	entities = iampkg.DeduplicateByARN(entities)

	// Return 2 results: entities + relationships
	return []plugin.Result{
		{
			Data: entities,
			Metadata: map[string]any{
				"module":    m.ID(),
				"type":      "entities",
				"accountID": accountID,
				"count":     len(entities),
			},
		},
		{
			Data: fullResults,
			Metadata: map[string]any{
				"module": m.ID(),
				"type":   "iam_relationships",
				"count":  len(fullResults),
			},
		},
	}, nil
}

// graphResolveRegions resolves "all" to actual enabled regions
func graphResolveRegions(regions []string, profile, profileDir string) ([]string, error) {
	if len(regions) == 1 && strings.ToLower(regions[0]) == "all" {
		return awshelpers.EnabledRegions(profile, profileDir)
	}
	return regions, nil
}
