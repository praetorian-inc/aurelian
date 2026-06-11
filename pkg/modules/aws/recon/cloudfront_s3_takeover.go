package recon

import (
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	helpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	cf "github.com/praetorian-inc/aurelian/pkg/aws/cloudfront"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AWSCloudFrontS3TakeoverModule{})
}

type CloudFrontS3TakeoverConfig struct {
	plugin.AWSCommonRecon
}

type AWSCloudFrontS3TakeoverModule struct {
	CloudFrontS3TakeoverConfig
}

func (m *AWSCloudFrontS3TakeoverModule) ID() string                { return "cloudfront-s3-takeover" }
func (m *AWSCloudFrontS3TakeoverModule) Name() string              { return "CloudFront S3 Origin Takeover" }
func (m *AWSCloudFrontS3TakeoverModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSCloudFrontS3TakeoverModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSCloudFrontS3TakeoverModule) OpsecLevel() string        { return "moderate" }
func (m *AWSCloudFrontS3TakeoverModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSCloudFrontS3TakeoverModule) Description() string {
	return "Detects CloudFront distributions with S3 origins pointing to non-existent buckets, " +
		"which could allow attackers to take over the domain by creating the missing bucket. " +
		"Also identifies Route53 records pointing to vulnerable distributions."
}

func (m *AWSCloudFrontS3TakeoverModule) References() []string {
	return cf.TakeoverReferences
}

func (m *AWSCloudFrontS3TakeoverModule) SupportedResourceTypes() []string {
	return []string{"AWS::CloudFront::Distribution"}
}

func (m *AWSCloudFrontS3TakeoverModule) Parameters() any {
	return &m.CloudFrontS3TakeoverConfig
}

func (m *AWSCloudFrontS3TakeoverModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.CloudFrontS3TakeoverConfig

	// CloudFront is a global service — always us-east-1.
	awsCfg, err := helpers.NewAWSConfig(helpers.AWSConfigInput{
		Region:     "us-east-1",
		Profile:    c.Profile,
		ProfileDir: c.ProfileDir,
	})
	if err != nil {
		return fmt.Errorf("create AWS config: %w", err)
	}

	accountID, err := helpers.GetAccountId(awsCfg)
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	inputs, err := collectInputs(c.AWSCommonRecon, m.SupportedResourceTypes())
	if err != nil {
		return fmt.Errorf("collect inputs: %w", err)
	}

	lister := cf.NewLister(cloudfront.NewFromConfig(awsCfg), accountID)
	checker := cf.NewChecker(s3.NewFromConfig(awsCfg), route53.NewFromConfig(awsCfg))

	inputPipeline := pipeline.From(inputs...)
	listed := pipeline.New[cf.DistributionInfo]()
	pipeline.Pipe(inputPipeline, lister.List, listed)

	findings := pipeline.New[cf.Finding]()
	pipeline.Pipe(listed, checker.Check, findings)

	pipeline.Pipe(findings, buildTakeoverRisk, out)
	return out.Wait()
}

func buildTakeoverRisk(f cf.Finding, out *pipeline.P[model.AurelianModel]) error {
	risk, err := cf.NewTakeoverRisk(f)
	if err != nil {
		slog.Warn("failed to build cloudfront takeover risk", "distribution", f.DistributionID, "error", err)
		return nil // preserve skip-on-failure; don't break the pipeline
	}
	out.Send(risk)
	return nil
}
