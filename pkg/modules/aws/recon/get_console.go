package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws"
	"github.com/praetorian-inc/nebula/pkg/links/general"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("aws", "recon", AWSGetConsole.Metadata().Properties()["id"].(string), *AWSGetConsole)
}

var AWSGetConsole = chain.NewModule(
	cfg.NewMetadata(
		"AWS Get Console URL",
		"Generate a federated sign-in URL for the AWS Console using temporary credentials",
	).WithProperties(map[string]any{
		"id":          "get-console",
		"platform":    "aws",
		"opsec_level": "moderate",
		"authors":     []string{"Bernard Yip", "Praetorian"},
		"references": []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_enable-regions.html",
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-signing.html",
		},
	}),
).WithLinks(
	general.NewGeneratorLink, // Generates initial trigger data
	aws.NewAWSConsoleURLLink, // Generates console URL
).WithOutputters(
	outputters.NewURLConsoleOutputter,
).WithInputParam(
	options.AwsProfile(),
).WithInputParam(
	options.AwsRegions(),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "get-console"),
).WithAutoRun()
