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
	registry.Register("aws", "analyze", AWSKnownAccountId.Metadata().Properties()["id"].(string), *AWSKnownAccountId)
}

var AWSKnownAccountId = chain.NewModule(
	cfg.NewMetadata(
		"AWS Known Account ID",
		"Looks up AWS account IDs against known public accounts including AWS-owned accounts and canary tokens",
	).WithProperties(map[string]any{
		"id":          "known-account-id",
		"platform":    "aws",
		"opsec_level": "safe",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://github.com/rupertbg/aws-public-account-ids/tree/master",
			"https://github.com/fwdcloudsec/known_aws_accounts",
			"https://github.com/trufflesecurity/trufflehog/blob/4cd055fe3f13b5e17fcb19553c623f1f2720e9f3/pkg/detectors/aws/access_keys/canary.go#L16",
		},
	}).WithChainInputParam(
		options.AwsAccountId().Name(),
	),
).WithLinks(
	aws.NewKnownAccountID,
).WithOutputters(
	output.NewJSONOutputter,
	output.NewConsoleOutputter,
).WithInputParam(
	options.AwsAccountId(),
)
