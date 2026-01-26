package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("aws", "recon", AwsCdkBucketTakeover.Metadata().Properties()["id"].(string), *AwsCdkBucketTakeover)
}

var AwsCdkBucketTakeover = chain.NewModule(
	cfg.NewMetadata(
		"CDK Bucket Takeover Detection",
		"Detects AWS CDK S3 bucket takeover vulnerabilities by identifying missing CDK staging buckets and insecure IAM policies. Scans for CDK bootstrap roles and validates associated S3 buckets for potential account takeover risks.",
	).WithProperties(map[string]any{
		"id":          "cdk-bucket-takeover",
		"platform":    "aws",
		"opsec_level": "safe",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover/",
			"https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping.html",
			"https://github.com/avishayil/cdk-bucket-takeover-scanner",
		},
	}),
).WithLinks(
	aws.NewAwsCdkQualifierDiscovery,
	aws.NewAwsCdkRoleDetector,
	aws.NewAwsCdkBootstrapChecker,
	aws.NewAwsCdkBucketValidator,
	aws.NewAwsCdkPolicyAnalyzer,
).WithOutputters(
	outputters.NewRiskConsoleOutputter,
	outputters.NewRuntimeJSONOutputter,
	outputters.NewProofFileOutputter,
).WithInputParam(
	options.AwsProfile(),
).WithInputParam(
	options.AwsRegions(),
).WithInputParam(
	options.AwsCdkQualifiers(),
).WithInputParam(
	cfg.NewParam[string]("filename", "Base filename for output").
		WithDefault("").
		WithShortcode("f"),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "cdk-bucket-takeover"),
).WithAutoRun()
