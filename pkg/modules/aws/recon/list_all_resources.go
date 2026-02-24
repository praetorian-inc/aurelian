package recon

import (
	"fmt"

	cclist "github.com/praetorian-inc/aurelian/pkg/aws/cloudcontrol"
	"github.com/praetorian-inc/aurelian/pkg/emitter"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
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

func (m *AWSListAllResourcesModule) Run(cfg plugin.Config, emit func(models ...model.AurelianModel)) error {
	c := m.ListAllConfig

	resolvedRegions, err := resolveRegions(c.Regions, c.Profile, c.ProfileDir)
	if err != nil {
		return fmt.Errorf("failed to resolve regions: %w", err)
	}

	lister := cclist.NewCloudControlLister(c.AWSCommonRecon, resolvedRegions)

	e1 := emitter.From(selectResourceTypes(c.ScanType)...)
	e2 := emitter.New[output.AWSResource]()
	emitter.Pipe(e1, e2, lister.List)

	for r := range e2.Range() {
		emit(r)
	}

	return e2.Wait()
}
