package recon

import (
	"fmt"

	cclist "github.com/praetorian-inc/aurelian/pkg/aws/cloudcontrol"
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
type AWSListAllResourcesModule struct{}

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

func (m *AWSListAllResourcesModule) Parameters() []plugin.Parameter {
	return plugin.ParametersFrom(ListAllConfig{})
}

func (m *AWSListAllResourcesModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	var c ListAllConfig
	if err := plugin.Bind(cfg, &c); err != nil {
		return nil, fmt.Errorf("parameter validation failed: %w", err)
	}

	resolvedRegions, err := resolveRegions(c.Regions, c.Profile, c.ProfileDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve regions: %w", err)
	}

	results, err := cclist.ListAll(cfg.Context, cclist.ListAllOptions{
		ResourceTypes: selectResourceTypes(c.ScanType),
		Regions:       resolvedRegions,
		Concurrency:   c.Concurrency,
		Profile:       c.Profile,
		ProfileDir:    c.ProfileDir,
	})
	if err != nil {
		return nil, err
	}

	return []plugin.Result{
		{
			Data: results,
			Metadata: map[string]any{
				"module":   m.ID(),
				"platform": m.Platform(),
				"regions":  resolvedRegions,
			},
		},
	}, nil
}
