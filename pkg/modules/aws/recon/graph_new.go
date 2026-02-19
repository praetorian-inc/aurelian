package recon

import (
	"github.com/praetorian-inc/aurelian/pkg/plugin"
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
	return nil, nil
}
