package analyze

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/janus-framework/pkg/output"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

func init() {
	registry.Register("aws", "analyze", AWSAccessKeyToAccountId.Metadata().Properties()["id"].(string), *AWSAccessKeyToAccountId)
}

var AWSAccessKeyToAccountId = chain.NewModule(
	cfg.NewMetadata(
		"AWS Access Key to Account ID",
		"Extract AWS Account ID from AWS Access Key ID",
	).WithProperties(map[string]any{
		"id":          "access-key-to-account-id",
		"platform":    "aws",
		"opsec_level": "safe",
		"authors":     []string{"Praetorian"},
	}).WithChainInputParam(
		options.AwsAccessKeyId().Name(),
	),
).WithLinks(
	aws.NewAwsAccessKeyToAccountId,
).WithOutputters(
	output.NewConsoleOutputter,
).WithInputParam(
	options.AwsAccessKeyId(),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "access-key-to-account-id"),
)
