package recon

import (
	cclist "github.com/praetorian-inc/aurelian/pkg/aws/cloudcontrol"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AWSListAllResourcesModule{})
}

// ListAllConfig holds the typed parameters for list-all module.
type ListAllConfig struct {
	plugin.AWSCommonRecon
	ScanType string `param:"scan-type"   desc:"Scan type - 'full' for all resources or 'summary' for key services" default:"full" shortcode:"s" enum:"full,summary"`
}

// AWSListAllResourcesModule enumerates all resources using Cloud Control API
type AWSListAllResourcesModule struct {
	ListAllConfig
}

func (m *AWSListAllResourcesModule) ID() string                { return "list-all" }
func (m *AWSListAllResourcesModule) Name() string              { return "AWS List All Resources" }
func (m *AWSListAllResourcesModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSListAllResourcesModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSListAllResourcesModule) OpsecLevel() string        { return "moderate" }
func (m *AWSListAllResourcesModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSListAllResourcesModule) Description() string {
	return "List resources in an AWS account using CloudControl API. Supports 'full' scan for all resources or 'summary' scan for key services. Can scan multiple regions concurrently."
}

func (m *AWSListAllResourcesModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/cloudcontrolapi/latest/APIReference/Welcome.html",
		"https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/supported-resources.html",
	}
}

func (m *AWSListAllResourcesModule) SupportedResourceTypes() []string {
	return []string{
		"AWS::Organizations::Account",
		"AWS::Organizations::Organization",
	}
}

func (m *AWSListAllResourcesModule) Parameters() any {
	return &m.ListAllConfig
}

func (m *AWSListAllResourcesModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.ListAllConfig

	lister := cclist.NewCloudControlLister(c.AWSCommonRecon)
	resourceTypes, err := resolveRequestedResourceTypes(c.ResourceType, selectResourceTypes(c.ScanType))
	if err != nil {
		return err
	}

	resourceTypePipeline := pipeline.From(resourceTypes...)
	listed := pipeline.New[output.AWSResource]()
	pipeline.Pipe(resourceTypePipeline, lister.ListByType, listed)

	for r := range listed.Range() {
		out.Send(r)
	}

	return listed.Wait()
}
