package recon

import (
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/aws/cloudfront"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AWSCloudFrontS3TakeoverModule{})
}

type CloudFrontS3TakeoverConfig struct {
	plugin.AWSReconBase
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
	return []string{
		"https://labs.detectify.com/writeups/hostile-subdomain-takeover-using-cloudfront/",
		"https://www.hackerone.com/application-security/guide-subdomain-takeovers",
		"https://github.com/EdOverflow/can-i-take-over-xyz",
	}
}

func (m *AWSCloudFrontS3TakeoverModule) SupportedResourceTypes() []string {
	return []string{"AWS::CloudFront::Distribution"}
}

func (m *AWSCloudFrontS3TakeoverModule) Parameters() any {
	return &m.CloudFrontS3TakeoverConfig
}

func (m *AWSCloudFrontS3TakeoverModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	c := m.CloudFrontS3TakeoverConfig

	result, err := cloudfront.Scan(cfg.Context, cloudfront.ScanOptions{
		Profile:    c.Profile,
		ProfileDir: c.ProfileDir,
	})
	if err != nil {
		return nil, fmt.Errorf("cloudfront scan: %w", err)
	}

	return []plugin.Result{
		{
			Data: result.Risks,
			Metadata: map[string]any{
				"module":    m.ID(),
				"platform":  string(m.Platform()),
				"accountID": result.AccountID,
			},
		},
	}, nil
}
