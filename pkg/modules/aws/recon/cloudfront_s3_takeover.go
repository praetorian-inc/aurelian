package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws/cloudfront"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("aws", "recon", AwsCloudFrontS3Takeover.Metadata().Properties()["id"].(string), *AwsCloudFrontS3Takeover)
}

var AwsCloudFrontS3Takeover = chain.NewModule(
	cfg.NewMetadata(
		"CloudFront S3 Origin Takeover Detection",
		"Detects CloudFront distributions with S3 origins pointing to non-existent buckets, which could allow attackers to take over the domain by creating the missing bucket. Also identifies Route53 records pointing to vulnerable distributions.",
	).WithProperties(map[string]any{
		"id":          "cloudfront-s3-takeover",
		"platform":    "aws",
		"opsec_level": "safe",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://labs.detectify.com/writeups/hostile-subdomain-takeover-using-cloudfront/",
			"https://www.hackerone.com/application-security/guide-subdomain-takeovers",
			"https://github.com/EdOverflow/can-i-take-over-xyz",
		},
	}),
).WithLinks(
	cloudfront.NewCloudFrontDistributionEnumerator,
	cloudfront.NewCloudFrontS3OriginChecker,
	cloudfront.NewRoute53DomainFinder,
).WithOutputters(
	outputters.NewRiskConsoleOutputter,
	outputters.NewRuntimeJSONOutputter,
	outputters.NewRuntimeMarkdownOutputter,
).WithInputParam(
	options.AwsProfile(),
).WithInputParam(
	options.AwsRegions(),
).WithInputParam(
	cfg.NewParam[string]("filename", "Base filename for output").
		WithDefault("cloudfront-s3-takeover").
		WithShortcode("f"),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "cloudfront-s3-takeover"),
).WithAutoRun()
