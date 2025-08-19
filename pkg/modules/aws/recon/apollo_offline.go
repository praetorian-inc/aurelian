package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("aws", "recon", ApolloOffline.Metadata().Properties()["id"].(string), *ApolloOffline)
}

var ApolloOffline = chain.NewModule(
	cfg.NewMetadata(
		"AWS Apollo Offline",
		"Analyze AWS access control details from pre-collected JSON files using graph analysis",
	).WithProperties(map[string]any{
		"id":          "apollo-offline",
		"platform":    "aws", 
		"opsec_level": "none", // No API calls
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html",
			"https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListPolicies.html",
		},
	}),
).WithLinks(
	aws.NewAwsApolloOfflineControlFlow,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "apollo-offline"),
).WithAutoRun()