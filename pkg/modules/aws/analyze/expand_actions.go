package analyze

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/iam/aws"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("aws", "analyze", AWSExpandActions.Metadata().Properties()["id"].(string), *AWSExpandActions)
}

var AWSExpandActions = chain.NewModule(
	cfg.NewMetadata(
		"AWS Expand Actions",
		"Expand AWS IAM actions to include all possible actions",
	).WithProperties(map[string]any{
		"id":          "expand-actions",
		"platform":    "aws",
		"opsec_level": "low",
		"authors":     []string{"Praetorian"},
	}).WithChainInputParam(
		options.AwsAction().Name(),
	),
).WithLinks(
	aws.NewAWSExpandActionsLink,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
).WithInputParam(
	options.AwsAction(),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "expand-actions"),
)
