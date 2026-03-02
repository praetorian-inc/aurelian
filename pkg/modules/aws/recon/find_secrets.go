package recon

import (
	"github.com/praetorian-inc/aurelian/pkg/aws/secrets"
	cclist "github.com/praetorian-inc/aurelian/pkg/aws/cloudcontrol"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/scanner"
	"github.com/praetorian-inc/titus/pkg/validator"
)

func init() {
	plugin.Register(&AWSFindSecretsModule{})
}

// FindSecretsConfig holds the typed parameters for find-secrets module.
type FindSecretsConfig struct {
	plugin.AWSCommonRecon
	MaxEvents   int    `param:"max-events"   desc:"Maximum number of log events to fetch per log group (CloudWatch Logs)" default:"10000"`
	MaxStreams  int    `param:"max-streams"   desc:"Maximum number of log streams to sample per log group (CloudWatch Logs)" default:"10"`
	NewestFirst bool   `param:"newest-first"  desc:"Fetch newest events first instead of oldest (CloudWatch Logs)" default:"false"`
	DBPath      string `param:"db-path"       desc:"Path for the Titus SQLite database (default: aurelian-output/titus.db)" default:""`
	Verify      bool   `param:"verify"        desc:"Validate detected secrets against their source APIs" default:"false"`
}

// ScanOpts converts the module config into a secrets.ScanOptions.
func (c *FindSecretsConfig) ScanOpts() secrets.ScanOptions {
	return secrets.ScanOptions{
		Profile:     c.Profile,
		ProfileDir:  c.ProfileDir,
		Concurrency: c.Concurrency,
		MaxEvents:   c.MaxEvents,
		MaxStreams:   c.MaxStreams,
		NewestFirst: c.NewestFirst,
	}
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

func (m *AWSFindSecretsModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.FindSecretsConfig

	ps, err := scanner.NewPersistentScanner(c.DBPath)
	if err != nil {
		return err
	}
	defer ps.Close()

	var ve *validator.Engine
	if c.Verify {
		ve = validator.NewEngine(c.Concurrency, validator.NewAWSValidator())
	}

	lister := cclist.NewCloudControlLister(c.AWSCommonRecon)
	resourceTypes, err := resolveRequestedResourceTypes(c.ResourceType, secrets.SupportedResourceTypes())
	if err != nil {
		return err
	}

	// Stage 1: List resources via CloudControl
	resourceTypePipeline := pipeline.From(resourceTypes...)
	listed := pipeline.New[output.AWSResource]()
	pipeline.Pipe(resourceTypePipeline, lister.List, listed)

	// Stage 2: Extract content and scan for secrets
	scanned := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(listed, secrets.NewResourceScanner(c.ScanOpts(), ps, ve), scanned)

	for finding := range scanned.Range() {
		out.Send(finding)
	}
	return scanned.Wait()
}
