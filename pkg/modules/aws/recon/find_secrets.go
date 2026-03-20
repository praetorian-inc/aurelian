package recon

import (
	"fmt"
	"log/slog"

	cclist "github.com/praetorian-inc/aurelian/pkg/aws/enumeration"
	"github.com/praetorian-inc/aurelian/pkg/aws/extraction"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/secrets"
)

func init() {
	plugin.Register(&AWSFindSecretsModule{})
}

// FindSecretsConfig holds the typed parameters for the find-secrets module.
type FindSecretsConfig struct {
	plugin.AWSCommonRecon
	secrets.ScannerConfig
	MaxEvents  int `param:"max-events" desc:"Max log events per log group" default:"10000"`
	MaxStreams int `param:"max-streams" desc:"Max streams to sample per log group" default:"10"`
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
	return []string{
		"AWS::EC2::Instance",
		"AWS::Lambda::Function",
		"AWS::CloudFormation::Stack",
		"AWS::Logs::LogGroup",
		"AWS::ECS::TaskDefinition",
		"AWS::SSM::Document",
		"AWS::StepFunctions::StateMachine",
		// TODO: AWS::ECR::Repository — container image scanning deferred to follow-up PR.
	}
}

func (m *AWSFindSecretsModule) Parameters() any {
	return &m.FindSecretsConfig
}

func (m *AWSFindSecretsModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.FindSecretsConfig
	if c.DBPath == "" {
		c.DBPath = secrets.DefaultDBPath(c.OutputDir)
	}

	var s secrets.SecretScanner
	if err := s.Start(c.ScannerConfig); err != nil {
		return fmt.Errorf("failed to create Titus scanner: %w", err)
	}
	defer func() {
		if closeErr := s.Close(); closeErr != nil {
			slog.Warn("failed to close Titus scanner", "error", closeErr)
		}
	}()

	cfg.Info("scanning %d resource types for secrets", len(m.SupportedResourceTypes()))

	inputs, err := collectInputs(m.AWSCommonRecon, m.SupportedResourceTypes())
	if err != nil {
		return fmt.Errorf("failed to collect inputs: %w", err)
	}

	lister := cclist.NewEnumerator(c.AWSCommonRecon)
	inputPipeline := pipeline.From(inputs...)
	listed := pipeline.New[output.AWSResource]()
	pipeline.Pipe(inputPipeline, lister.List, listed, &pipeline.PipeOpts{
		Progress: cfg.Log.ProgressFunc("listing resources"),
	})

	extractor := extraction.NewAWSExtractor(c.AWSCommonRecon, extraction.Config{
		MaxEvents:  c.MaxEvents,
		MaxStreams: c.MaxStreams,
	})

	extracted := pipeline.New[output.ScanInput]()
	pipeline.Pipe(listed, extractor.Extract, extracted, &pipeline.PipeOpts{
		Progress:    cfg.Log.ProgressFunc("extracting content"),
		Concurrency: m.Concurrency,
	})

	scanned := pipeline.New[secrets.SecretScanResult]()
	pipeline.Pipe(extracted, s.Scan, scanned, &pipeline.PipeOpts{
		Progress: cfg.Log.ProgressFunc("scanning for secrets"),
	})
	pipeline.Pipe(scanned, secrets.RiskFromScanResult, out)

	if err := out.Wait(); err != nil {
		return err
	}
	cfg.Success("secret scanning complete")
	return nil
}

