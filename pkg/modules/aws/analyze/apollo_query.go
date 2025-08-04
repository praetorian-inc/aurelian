package analyze

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/janus-framework/pkg/output"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("aws", "analyze", ApolloQuery.Metadata().Properties()["id"].(string), *ApolloQuery)
}

var ApolloQuery = chain.NewModule(
	cfg.NewMetadata(
		"Apollo Query",
		"Runs a query against the Apollo graph database",
	).WithProperties(map[string]any{
		"id":          "apollo-query",
		"platform":    "aws",
		"opsec_level": "safe",
		"authors":     []string{"Praetorian"},
		"references":  []string{},
	}).WithChainInputParam(
		options.Query().Name(),
	),
).WithLinks(
	aws.NewApolloQuery,
).WithOutputters(
	output.NewJSONOutputter,
	outputters.NewRiskConsoleOutputter,
	outputters.NewRiskCSVOutputter,
).WithInputParam(
	options.Query(),
)
