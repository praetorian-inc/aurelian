package recon

import (
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/aws/secrets"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AWSFindSecretsModule{})
}

// FindSecretsConfig holds the typed parameters for find-secrets module.
type FindSecretsConfig struct {
	plugin.AWSCommonRecon
	MaxEvents   int  `param:"max-events"   desc:"Maximum number of log events to fetch per log group (CloudWatch Logs)" default:"10000"`
	MaxStreams  int  `param:"max-streams"   desc:"Maximum number of log streams to sample per log group (CloudWatch Logs)" default:"10"`
	NewestFirst bool `param:"newest-first"  desc:"Fetch newest events first instead of oldest (CloudWatch Logs)" default:"false"`
	DBPath      string `param:"db-path"      desc:"Path for the Titus SQLite database (default: aurelian-output/titus.db)" default:""`
}

// AWSFindSecretsModule enumerates AWS resources and scans them for secrets.
type AWSFindSecretsModule struct {
	FindSecretsConfig
}

func (m *AWSFindSecretsModule) ID() string                { return "find-secrets" }
func (m *AWSFindSecretsModule) Name() string              { return "AWS Find Secrets" }
func (m *AWSFindSecretsModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSFindSecretsModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSFindSecretsModule) OpsecLevel() string        { return "moderate" }
func (m *AWSFindSecretsModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSFindSecretsModule) Description() string {
	return "Enumerate AWS resources and scan their content for secrets using Titus. Supports EC2 UserData, Lambda code, CloudFormation templates, CloudWatch Logs, ECS task definitions, SSM documents, and Step Functions state machines."
}

func (m *AWSFindSecretsModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/supported-resources.html",
	}
}

func (m *AWSFindSecretsModule) SupportedResourceTypes() []string {
	return secrets.SupportedResourceTypes()
}

func (m *AWSFindSecretsModule) Parameters() any {
	return &m.FindSecretsConfig
}

func (m *AWSFindSecretsModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	c := m.FindSecretsConfig

	findings, err := secrets.FindSecrets(cfg.Context, secrets.ScanOptions{
		Profile:       c.Profile,
		ProfileDir:    c.ProfileDir,
		Regions:       c.Regions,
		Concurrency:   c.Concurrency,
		ResourceTypes: c.ResourceType,
		MaxEvents:     c.MaxEvents,
		MaxStreams:     c.MaxStreams,
		NewestFirst:   c.NewestFirst,
		DBPath:        c.DBPath,
	})
	if err != nil {
		return nil, fmt.Errorf("find-secrets: %w", err)
	}

	return []plugin.Result{
		{
			Data: findings,
			Metadata: map[string]any{
				"module":   m.ID(),
				"platform": m.Platform(),
			},
		},
	}, nil
}
