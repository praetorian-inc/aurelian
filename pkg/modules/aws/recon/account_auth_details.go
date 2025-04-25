package recon

import (
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	//AwsAuthorizationDetails.New().Initialize()
	registry.Register("aws", "recon", "account-auth-detials", *AwsAuthorizationDetails)
}

var AwsAuthorizationDetails = chain.NewModule(
	cfg.NewMetadata(
		"AWS Get Account Authorization Details",
		"Get authorization details in an AWS account.",
	).WithProperties(map[string]any{
		"platform":    "aws",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html",
			"https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/iam#Client.GetAccountAuthorizationDetails",
		},
	}).WithChainInputParam(
		options.AwsResourceType().Name()),
).WithLinks(
	aws.NewJanusAWSAuthorizationDetails,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
)
