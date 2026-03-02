package recon

import (
	"encoding/json"
	"log/slog"

	cclist "github.com/praetorian-inc/aurelian/pkg/aws/cloudcontrol"
	"github.com/praetorian-inc/aurelian/pkg/aws/enrichment"
	"github.com/praetorian-inc/aurelian/pkg/aws/publicaccess"
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
	plugin.OrgPoliciesParam
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

	lister := cclist.NewCloudControlLister(c.AWSCommonRecon)
	resourceTypes, err := resolveRequestedResourceTypes(c.ResourceType, publicaccess.SupportedResourceTypes())
	if err != nil {
		return err
	}

	resourceTypePipeline := pipeline.From(resourceTypes...)
	listed := pipeline.New[output.AWSResource]()
	pipeline.Pipe(resourceTypePipeline, lister.List, listed)

	// Enrich resources with properties not available from CloudControl
	// (e.g. RDS PubliclyAccessible, Cognito self-signup, Lambda function URL auth type).
	enricher := enrichment.NewAWSEnricher(c.AWSCommonRecon)
	enriched := pipeline.New[output.AWSResource]()
	pipeline.Pipe(listed, enricher.Enrich, enriched)

	evaluator := publicaccess.NewResourceEvaluator(c.AWSCommonRecon, c.OrgPolicies)
	evaluated := pipeline.New[publicaccess.PublicAccessResult]()
	pipeline.Pipe(enriched, evaluator.Evaluate, evaluated)
	pipeline.Pipe(evaluated, riskFromResult, out)

	return out.Wait()
}

func riskFromResult(r publicaccess.PublicAccessResult, out *pipeline.P[model.AurelianModel]) error {
	if r.AWSResource == nil {
		return nil
	}

	var severity output.RiskSeverity
	switch r.AWSResource.AccessLevel {
	case output.AccessLevelPublic:
		severity = output.RiskSeverityHigh
	case output.AccessLevelNeedsTriage:
		severity = output.RiskSeverityMedium
	default:
		return nil
	}

	resourceID := r.AWSResource.ResourceID
	impactedARN := r.AWSResource.ARN
	if impactedARN == "" {
		impactedARN = resourceID
	}

	r.AWSResource = nil
	ctx, err := json.Marshal(r)
	if err != nil {
		slog.Warn("failed to build risk context", "resource", resourceID, "error", err)
		return nil
	}

	out.Send(output.AurelianRisk{
		Name:        "public-aws-resource",
		Severity:    severity,
		ImpactedARN: impactedARN,
		Context:     ctx,
	})
	return nil
}
