package recon

import (
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	cclist "github.com/praetorian-inc/aurelian/pkg/aws/cloudcontrol"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/modules/aws/recon/secrets"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/scanner"
)

func init() {
	plugin.Register(&AWSFindSecretsModule{})
}

// supportedSecretResourceTypes lists the resource types this module can scan for secrets.
var supportedSecretResourceTypes = []string{
	"AWS::EC2::Instance",
	"AWS::Lambda::Function",
	"AWS::CloudFormation::Stack",
	"AWS::Logs::LogGroup",
	"AWS::ECS::TaskDefinition",
	"AWS::SSM::Document",
	"AWS::StepFunctions::StateMachine",
	// TODO: AWS::ECR::Repository — container image scanning deferred to follow-up PR.
}

// FindSecretsConfig holds the typed parameters for the find-secrets module.
type FindSecretsConfig struct {
	plugin.AWSCommonRecon
	DBPath     string `param:"db-path" desc:"Path for Titus SQLite database" default:""`
	MaxEvents  int    `param:"max-events" desc:"Max log events per log group" default:"10000"`
	MaxStreams int    `param:"max-streams" desc:"Max streams to sample per log group" default:"10"`
}

// AWSFindSecretsModule scans AWS resources for hardcoded secrets using Titus.
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
	return "Enumerates AWS resources via Cloud Control, extracts content likely to contain " +
		"hardcoded secrets (EC2 user data, Lambda code, CloudFormation templates, CloudWatch logs, " +
		"ECS task definitions, SSM documents, Step Functions executions), and scans with Titus."
}

func (m *AWSFindSecretsModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/supported-resources.html",
	}
}

func (m *AWSFindSecretsModule) SupportedResourceTypes() []string {
	return supportedSecretResourceTypes
}

func (m *AWSFindSecretsModule) Parameters() any {
	return &m.FindSecretsConfig
}

func (m *AWSFindSecretsModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.FindSecretsConfig

	ps, err := scanner.NewPersistentScanner(c.DBPath)
	if err != nil {
		return fmt.Errorf("failed to create Titus scanner: %w", err)
	}
	defer func() {
		if closeErr := ps.Close(); closeErr != nil {
			slog.Warn("failed to close Titus scanner", "error", closeErr)
		}
	}()

	slog.Info("find-secrets: Titus scanner initialized", "db", ps.DBPath())

	resourceTypes, err := resolveRequestedResourceTypes(c.ResourceType, supportedSecretResourceTypes)
	if err != nil {
		return err
	}

	lister := cclist.NewCloudControlLister(c.AWSCommonRecon)
	resourceTypePipeline := pipeline.From(resourceTypes...)
	listed := pipeline.New[output.AWSResource]()
	pipeline.Pipe(resourceTypePipeline, lister.List, listed)

	extractorCfg := secrets.ExtractorConfig{
		AWSConfigFactory: func(region string) (aws.Config, error) {
			return awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
				Region:     region,
				Profile:    c.Profile,
				ProfileDir: c.ProfileDir,
			})
		},
		MaxEvents:  c.MaxEvents,
		MaxStreams: c.MaxStreams,
	}

	extracted := pipeline.New[secrets.ScanInput]()
	pipeline.Pipe(listed, secrets.ExtractContent(extractorCfg), extracted)

	scanned := pipeline.New[output.SecretFinding]()
	pipeline.Pipe(extracted, secrets.ScanForSecrets(ps), scanned)

	for finding := range scanned.Range() {
		out.Send(finding)
	}

	return scanned.Wait()
}
