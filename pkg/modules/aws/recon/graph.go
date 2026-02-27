package recon

import (
	"fmt"
	"log/slog"

	"golang.org/x/sync/errgroup"

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
	"github.com/praetorian-inc/aurelian/pkg/store"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	plugin.Register(&AWSGraphModule{})
}

type GraphConfig struct {
	plugin.AWSCommonRecon
	plugin.GraphOutputBase
	OrgPoliciesFile string `param:"org-policies-file" desc:"Path to Org Policies JSON file (optional)"`
}

// AWSGraphModule is a refactored version of AWSGraphModule.
type AWSGraphModule struct {
	GraphConfig

	gaadData              *types.AuthorizationAccountDetails
	resourcesWithPolicies store.Map[output.AWSResource]
	orgPols               *orgpolicies.OrgPolicies
	relationships         store.Map[output.AWSIAMRelationship]
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

func (m *AWSGraphModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	resolvedRegions, err := resolveRegions(m.Regions, m.Profile, m.ProfileDir)
	if err != nil {
		return fmt.Errorf("resolving regions: %w", err)
	}
	m.Regions = resolvedRegions

	if err := m.collectInputs(); err != nil {
		return fmt.Errorf("collecting inputs: %w", err)
	}

	if err := m.loadOrgPolicies(m.GraphConfig); err != nil {
		return fmt.Errorf("loading org policies: %w", err)
	}

	if err := m.analyzeIAMPermissions(); err != nil {
		return fmt.Errorf("analyzing IAM permissions: %w", err)
	}

	m.emitOutputs(out)
	return nil
}

func (m *AWSGraphModule) collectInputs() error {
	policyCollector := resourcepolicies.New(m.AWSCommonRecon)
	regions := m.Regions

	var eg errgroup.Group
	m.collectAccountAuthorizationDetails(&eg, m.GraphConfig)
	m.collectResourcesWithPolicies(&eg, m.GraphConfig, policyCollector, regions)
	if err := eg.Wait(); err != nil {
		return err
	}

	return nil
}

func (m *AWSGraphModule) collectAccountAuthorizationDetails(eg *errgroup.Group, c GraphConfig) {
	eg.Go(func() error {
		slog.Info("collecting account authorization details")
		g := gaad.New(c.AWSReconBase)
		gaadData, err := g.Get()
		if err != nil {
			return fmt.Errorf("collecting GAAD: %w", err)
		}
		slog.Info("GAAD collected",
			"account", gaadData.AccountID,
			"users", gaadData.Users.Len(),
			"roles", gaadData.Roles.Len(),
			"groups", gaadData.Groups.Len())
		m.gaadData = gaadData
		return nil
	})
}

func (m *AWSGraphModule) collectResourcesWithPolicies(eg *errgroup.Group, c GraphConfig, collector *resourcepolicies.ResourcePolicyCollector, resolvedRegions []string) {
	eg.Go(func() error {
		slog.Info("enumerating cloud resources and collecting policies",
			"types", len(collector.SupportedResourceTypes()), "regions", len(resolvedRegions))

		lister := cloudcontrol.NewCloudControlLister(c.AWSCommonRecon)
		listed, err := lister.Enumerate(collector.SupportedResourceTypes())
		if err != nil {
			return fmt.Errorf("enumerating resources: %w", err)
		}

		collected := pipeline.New[output.AWSResource]()
		pipeline.Pipe(listed, collector.Collect, collected)

		results := store.NewMap[output.AWSResource]()
		for r := range collected.Range() {
			key := r.ARN
			if key == "" {
				key = r.ResourceID
			}
			results.Set(key, r)
		}
		if err := collected.Wait(); err != nil {
			return fmt.Errorf("collecting resources with policies: %w", err)
		}

		slog.Info("resources with policies collected", "count", results.Len())
		m.resourcesWithPolicies = results
		return nil
	})
}

func (m *AWSGraphModule) loadOrgPolicies(c GraphConfig) error {
	orgPols := orgpolicies.NewDefaultOrgPolicies()

	if c.OrgPoliciesFile != "" {
		slog.Info("loading org policies", "file", c.OrgPoliciesFile)
		op, err := iampkg.LoadJSONFile[orgpolicies.OrgPolicies](c.OrgPoliciesFile)
		if err != nil {
			return fmt.Errorf("loading org policies: %w", err)
		}
		orgPols = op
	}

	m.orgPols = orgPols
	return nil
}

func (m *AWSGraphModule) analyzeIAMPermissions() error {
	slog.Info("analyzing IAM permissions")
	analyzer := gaadpkg.NewGaadAnalyzer()
	relationships, err := analyzer.Analyze(m.gaadData, m.orgPols, m.resourcesWithPolicies)
	if err != nil {
		return fmt.Errorf("analyzing permissions: %w", err)
	}

	slog.Info("IAM analysis complete", "relationships", relationships.Len())
	m.relationships = relationships
	return nil
}

func (m *AWSGraphModule) emitOutputs(out *pipeline.P[model.AurelianModel]) {
	gaadpkg.EmitGAADEntities(m.gaadData, m.gaadData.AccountID, func(i output.AWSIAMResource) {
		out.Send(i)
	})

	m.resourcesWithPolicies.Range(func(_ string, r output.AWSResource) bool {
		out.Send(r)
		return true
	})

	m.relationships.Range(func(_ string, r output.AWSIAMRelationship) bool {
		out.Send(r)
		return true
	})
}
