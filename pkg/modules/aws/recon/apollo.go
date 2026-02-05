package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/aurelian/internal/registry"
	"github.com/praetorian-inc/aurelian/pkg/links/aws"
	"github.com/praetorian-inc/aurelian/pkg/links/options"
	"github.com/praetorian-inc/aurelian/pkg/outputters"
)

func init() {
	registry.Register("aws", "recon", Apollo.Metadata().Properties()["id"].(string), *Apollo)

}

// Deprecated: Use ApolloV2 instead.
var Apollo = chain.NewModule(
	cfg.NewMetadata(
		"AWS Apollo",
		"Gather AWS access control details and analyze them using graph analysis",
	).WithProperties(map[string]any{
		"id":          "apollo",
		"platform":    "aws",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
	}).WithChainInputParam(
		options.AwsResourceType().Name(),
	),
).WithLinks(
	aws.NewAwsApolloControlFlow,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
	outputters.NewNeo4jGraphOutputter,
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "apollo"),
)
