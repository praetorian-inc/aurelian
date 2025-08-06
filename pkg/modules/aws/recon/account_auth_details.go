package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("aws", "recon", AwsAuthorizationDetails.Metadata().Properties()["id"].(string), *AwsAuthorizationDetails)
}

var AwsAuthorizationDetails = chain.NewModule(
	cfg.NewMetadata(
		"AWS Get Account Authorization Details",
		"Get authorization details in an AWS account.",
	).WithProperties(map[string]any{
		"id":          "account-auth-details",
		"platform":    "aws",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html",
			"https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/iam#Client.GetAccountAuthorizationDetails",
		},
	}),
).WithLinks(
	aws.NewJanusAWSAuthorizationDetails,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "account-auth-details"),
).WithAutoRun()
