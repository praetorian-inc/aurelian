package recon

import (
	"fmt"

	cclist "github.com/praetorian-inc/aurelian/pkg/aws/cloudcontrol"
	"github.com/praetorian-inc/aurelian/pkg/aws/resourcepolicies"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AWSResourcePoliciesModule{})
}

// ResourcePoliciesConfig holds the typed parameters for resource-policies module.
type ResourcePoliciesConfig struct {
	plugin.AWSCommonRecon
}

// AWSResourcePoliciesModule retrieves resource policies for supported AWS services
type AWSResourcePoliciesModule struct {
	ResourcePoliciesConfig
}

func (m *AWSResourcePoliciesModule) ID() string                { return "resource-policies" }
func (m *AWSResourcePoliciesModule) Name() string              { return "AWS Get Resource Policies" }
func (m *AWSResourcePoliciesModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSResourcePoliciesModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSResourcePoliciesModule) OpsecLevel() string        { return "moderate" }
func (m *AWSResourcePoliciesModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSResourcePoliciesModule) Description() string {
	return "Retrieves resource-based policies for AWS resources that support them (S3 buckets, Lambda functions, SNS topics, SQS queues, EFS file systems, OpenSearch/Elasticsearch domains). " +
		"Policies are added to the ResourcePolicy property of each resource."
}

func (m *AWSResourcePoliciesModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_identity-vs-resource.html",
		"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html",
	}
}

func (m *AWSResourcePoliciesModule) SupportedResourceTypes() []string {
	return resourcepolicies.New(m.AWSCommonRecon).SupportedResourceTypes()
}

func (m *AWSResourcePoliciesModule) Parameters() any {
	return &m.ResourcePoliciesConfig
}

func (m *AWSResourcePoliciesModule) Run(cfg plugin.Config, emit func(models ...model.AurelianModel)) error {
	c := m.ResourcePoliciesConfig

	resolvedRegions, err := resolveRegions(c.Regions, c.Profile, c.ProfileDir)
	if err != nil {
		return fmt.Errorf("failed to resolve regions: %w", err)
	}

	c.AWSCommonRecon.Regions = resolvedRegions
	lister := cclist.NewCloudControlLister(c.AWSCommonRecon)
	collector := resourcepolicies.New(c.AWSCommonRecon)

	p1 := pipeline.From(collector.SupportedResourceTypes()...)
	p2 := pipeline.New[output.AWSResource]()
	p3 := pipeline.New[output.AWSResource]()
	pipeline.Pipe(p1, lister.List, p2)
	pipeline.Pipe(p2, collector.Collect, p3)

	for r := range p3.Range() {
		emit(r)
	}

	return p3.Wait()
}
