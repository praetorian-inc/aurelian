package recon

import (
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/janus/pkg/output"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

func init() {
	registry.Register("aws", "recon", Apollo.Metadata().Properties()["id"].(string), *Apollo)

}

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
	output.NewJSONOutputter,
	output.NewConsoleOutputter,
)
