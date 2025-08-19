package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("aws", "recon", AwsResourcePolicies.Metadata().Properties()["id"].(string), *AwsResourcePolicies)
}

var AwsResourcePolicies = chain.NewModule(
	cfg.NewMetadata(
		"AWS Get Resource Policies",
		"Get resource policies for supported AWS resource types and output them keyed by ARN.",
	).WithProperties(map[string]any{
		"id":          "resource-policies",
		"platform":    "aws",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://docs.aws.amazon.com/lambda/latest/api/API_GetPolicy.html",
			"https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicy.html",
			"https://docs.aws.amazon.com/sns/latest/api/API_GetTopicAttributes.html",
			"https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_GetQueueAttributes.html",
		},
	}).WithChainInputParam(
		options.AwsResourceType().Name(),
	),
).WithLinks(
	aws.NewAwsResourcePolicyCollector,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "resource-policies"),
)