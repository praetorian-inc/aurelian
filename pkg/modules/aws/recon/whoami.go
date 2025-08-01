package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	AwsWhoami.New().Initialize()
	registry.Register("aws", "recon", AwsWhoami.Metadata().Properties()["id"].(string), *AwsWhoami)
}

var AwsWhoami = chain.NewModule(
	cfg.NewMetadata(
		"AWS Covert Whoami",
		"Performs covert whoami techniques using AWS APIs that don't log to CloudTrail.",
	).WithProperties(map[string]any{
		"id":          "whoami",
		"platform":    "aws",
		"opsec_level": "stealth",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://hackingthe.cloud/aws/enumeration/whoami/",
			"https://twitter.com/SpenGietz/status/1283846678194221057",
		},
	}),
).WithLinks(
	aws.NewAwsWhoami,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
).WithAutoRun()
