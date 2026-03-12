package recon

import (
	"fmt"

	cdkpkg "github.com/praetorian-inc/aurelian/pkg/aws/cdk"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() { plugin.Register(&AWSCdkBucketTakeoverModule{}) }

// CdkBucketTakeoverConfig holds the typed parameters for cdk-bucket-takeover module.
type CdkBucketTakeoverConfig struct {
	plugin.AWSCommonRecon
	Qualifiers []string `param:"cdk-qualifiers" desc:"CDK bootstrap qualifiers to check" default:"hnb659fds" shortcode:"q"`
}

// AWSCdkBucketTakeoverModule detects CDK S3 bucket takeover vulnerabilities.
type AWSCdkBucketTakeoverModule struct {
	CdkBucketTakeoverConfig
}

func (m *AWSCdkBucketTakeoverModule) ID() string                { return "cdk-bucket-takeover" }
func (m *AWSCdkBucketTakeoverModule) Name() string              { return "AWS CDK Bucket Takeover Detection" }
func (m *AWSCdkBucketTakeoverModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSCdkBucketTakeoverModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSCdkBucketTakeoverModule) OpsecLevel() string        { return "safe" }
func (m *AWSCdkBucketTakeoverModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSCdkBucketTakeoverModule) Description() string {
	return "Detects AWS CDK S3 bucket takeover vulnerabilities by identifying missing CDK staging " +
		"buckets and insecure IAM policies. Scans for CDK bootstrap roles and validates associated " +
		"S3 buckets for potential account takeover risks."
}

func (m *AWSCdkBucketTakeoverModule) References() []string {
	return []string{
		"https://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover/",
		"https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping.html",
		"https://github.com/avishayil/cdk-bucket-takeover-scanner",
	}
}

func (m *AWSCdkBucketTakeoverModule) SupportedResourceTypes() []string {
	return []string{"AWS::Organizations::Account"}
}

func (m *AWSCdkBucketTakeoverModule) Parameters() any {
	return &m.CdkBucketTakeoverConfig
}

func (m *AWSCdkBucketTakeoverModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.CdkBucketTakeoverConfig

	_, err := cdkpkg.Scan(cfg.Context, cdkpkg.ScanOptions{
		Qualifiers:  c.Qualifiers,
		Regions:     c.Regions,
		Concurrency: c.Concurrency,
		Profile:     c.Profile,
		ProfileDir:  c.ProfileDir,
		OnRisk:      func(r output.Risk) { out.Send(r) },
	})
	if err != nil {
		return fmt.Errorf("cdk scan: %w", err)
	}

	return nil
}
