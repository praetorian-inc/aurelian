package recon

import (
	"context"
	"fmt"
	"log/slog"

	cclist "github.com/praetorian-inc/aurelian/pkg/aws/cloudcontrol"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/aws/publicaccess"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AWSPublicResourcesModule{})
}

// PublicResourcesConfig holds the typed parameters for public-resources module.
type PublicResourcesConfig struct {
	plugin.AWSCommonRecon
	OrgPoliciesFile string `param:"org-policies" desc:"Path to org policies JSON file"`
}

// AWSPublicResourcesModule finds publicly accessible AWS resources through
// policy evaluation, property inspection, and enrichment.
type AWSPublicResourcesModule struct {
	PublicResourcesConfig
}

func (m *AWSPublicResourcesModule) ID() string                { return "public-resources" }
func (m *AWSPublicResourcesModule) Name() string              { return "AWS Public Resources" }
func (m *AWSPublicResourcesModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSPublicResourcesModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSPublicResourcesModule) OpsecLevel() string        { return "moderate" }
func (m *AWSPublicResourcesModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSPublicResourcesModule) Description() string {
	return "Finds publicly accessible AWS resources through policy evaluation, property inspection, and enrichment. " +
		"Combines resource listing, enrichment, policy fetching, and public access evaluation to identify " +
		"resources that are exposed to the internet or allow anonymous access."
}

func (m *AWSPublicResourcesModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_identity-vs-resource.html",
		"https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/supported-resources.html",
	}
}

func (m *AWSPublicResourcesModule) SupportedResourceTypes() []string {
	return publicaccess.SupportedResourceTypes()
}

func (m *AWSPublicResourcesModule) Parameters() any {
	return &m.PublicResourcesConfig
}

func (m *AWSPublicResourcesModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.PublicResourcesConfig

	// Load org policies if specified
	var orgPolicies *orgpolicies.OrgPolicies
	if c.OrgPoliciesFile != "" {
		var err error
		orgPolicies, err = iam.LoadJSONFile[orgpolicies.OrgPolicies](c.OrgPoliciesFile)
		if err != nil {
			return fmt.Errorf("failed to load org policies file: %w", err)
		}
	}

	lister := cclist.NewCloudControlLister(c.AWSCommonRecon)

	listed, err := lister.Enumerate(publicaccess.SupportedResourceTypes())
	if err != nil {
		return err
	}

	// Enrich resources with properties not available from CloudControl
	// (e.g. RDS PubliclyAccessible, Cognito self-signup, Lambda function URL auth type).
	enriched := pipeline.New[output.AWSResource]()
	pipeline.Pipe(listed, enrichResource(c.AWSCommonRecon), enriched)

	evaluator := publicaccess.NewResourceEvaluator(c.AWSCommonRecon, lister.Regions, orgPolicies)
	evaluated := pipeline.New[output.AWSResource]()
	pipeline.Pipe(enriched, evaluator.Evaluate, evaluated)

	for r := range evaluated.Range() {
		out.Send(r)
	}

	return evaluated.Wait()
}

// enrichResource returns a pipeline-compatible function that runs all registered
// enrichers for a resource's type before forwarding it downstream.
func enrichResource(opts plugin.AWSCommonRecon) func(output.AWSResource, *pipeline.P[output.AWSResource]) error {
	return func(r output.AWSResource, out *pipeline.P[output.AWSResource]) error {
		enrichers := plugin.GetEnrichers(r.ResourceType)
		if len(enrichers) > 0 {
			awsCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
				Region:     r.Region,
				Profile:    opts.Profile,
				ProfileDir: opts.ProfileDir,
			})
			if err != nil {
				slog.Warn("failed to create AWS config for enrichment, skipping enrichers",
					"resource", r.ResourceID, "region", r.Region, "error", err)
				out.Send(r)
				return nil
			}

			ecfg := plugin.EnricherConfig{
				Context:   context.Background(),
				AWSConfig: awsCfg,
			}
			for _, enrich := range enrichers {
				if err := enrich(ecfg, &r); err != nil {
					slog.Warn("enricher failed",
						"type", r.ResourceType,
						"resource", r.ResourceID,
						"error", err)
				}
			}
		}
		out.Send(r)
		return nil
	}
}
