package recon

import (
	"fmt"
	"log/slog"
	"strconv"

	"github.com/praetorian-inc/aurelian/pkg/aws/enrichment"
	cclist "github.com/praetorian-inc/aurelian/pkg/aws/enumeration"
	"github.com/praetorian-inc/aurelian/pkg/aws/publicaccess"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/publicresource"
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

	lister := cclist.NewEnumerator(c.AWSCommonRecon)
	defer func() { _ = lister.Close() }()

	inputs, err := collectInputs(m.AWSCommonRecon, m.SupportedResourceTypes())
	if err != nil {
		return fmt.Errorf("failed to collect inputs: %w", err)
	}

	cfg.Info("evaluating %d resource types for public access across %d regions", len(inputs), len(c.Regions))

	inputPipeline := pipeline.From(inputs...)
	listed := pipeline.New[output.AWSResource]()
	pipeline.Pipe(inputPipeline, lister.List, listed, &pipeline.PipeOpts{
		Progress: cfg.Log.ProgressFunc("listing resources"),
	})

	// Enrich resources with properties not available from CloudControl
	// (e.g. RDS PubliclyAccessible, Cognito self-signup, Lambda function URL auth type).
	enricher := enrichment.NewAWSEnricher(c.AWSCommonRecon)
	enriched := pipeline.New[output.AWSResource]()
	pipeline.Pipe(listed, enricher.Enrich, enriched, &pipeline.PipeOpts{
		Progress:    cfg.Log.ProgressFunc("enriching resources"),
		Concurrency: m.Concurrency,
	})

	evaluator := publicaccess.NewResourceEvaluator(c.AWSCommonRecon, c.OrgPolicies)
	evaluated := pipeline.New[publicaccess.PublicAccessResult]()
	pipeline.Pipe(enriched, evaluator.Evaluate, evaluated, &pipeline.PipeOpts{
		Progress:    cfg.Log.ProgressFunc("evaluating public access"),
		Concurrency: m.Concurrency,
	})
	pipeline.Pipe(evaluated, riskFromResult, out)

	if err := out.Wait(); err != nil {
		return err
	}

	cfg.Success("public access evaluation complete")
	return nil
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

	res := r.AWSResource
	resourceID := res.ARN
	if resourceID == "" {
		resourceID = res.ResourceID
	}

	risk, err := publicresource.NewRisk(publicresource.PublicResource{
		Provider:     "AWS",
		RiskName:     "public-aws-resource",
		ResourceType: res.ResourceType,
		ResourceID:   resourceID,
		ResourceName: res.DisplayName,
		Region:       res.Region,
		Scope:        res.AccountRef,
		ScopeLabel:   "AWS Account",
		Severity:     severity,
		Summary:      awsSummary(res, severity),
		Exposure: []publicresource.Fact{
			{Key: "Access Level", Value: string(res.AccessLevel)},
			{Key: "Public", Value: strconv.FormatBool(r.IsPublic)},
			{Key: "Needs Manual Triage", Value: strconv.FormatBool(r.NeedsManualTriage)},
		},
		Lists: []publicresource.NamedList{
			{Title: "Allowed Actions", Items: r.AllowedActions},
			{Title: "Evaluation Reasons", Items: r.EvaluationReasons},
			{Title: "Public Endpoints", Items: append(append([]string{}, res.URLs...), res.IPs...)},
		},
		Properties: res.Properties,
	})
	if err != nil {
		slog.Warn("failed to build public resource risk", "resource", resourceID, "error", err)
		return nil
	}

	out.Send(risk)
	return nil
}

// awsSummary describes the exposure for the proof's Summary section.
func awsSummary(res *output.AWSResource, severity output.RiskSeverity) string {
	if severity == output.RiskSeverityMedium {
		return fmt.Sprintf("AWS resource %s (%s) in account %s may be publicly accessible and requires manual triage.",
			res.ResourceID, res.ResourceType, res.AccountRef)
	}
	return fmt.Sprintf("AWS resource %s (%s) in account %s is publicly accessible.",
		res.ResourceID, res.ResourceType, res.AccountRef)
}
