package recon

import (
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/janus/pkg/output"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws"
	"github.com/praetorian-inc/nebula/pkg/links/general"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

func init() {
	AwsListResources.New().Initialize()
	registry.Register("aws", "recon", AwsListResources.Metadata().Properties()["id"].(string), *AwsListResources)
}

var AwsListResources = chain.NewModule(
	cfg.NewMetadata(
		"AWS List Resources",
		"List resources in an AWS account using Cloud Control API.",
	).WithProperties(map[string]any{
		"id":          "list",
		"platform":    "aws",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references": []string{
			"https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/what-is-cloudcontrol.html",
			"https://docs.aws.amazon.com/cloudcontrolapi/latest/userguide/supported-resources.html",
		},
	}).WithChainInputParam(options.AwsResourceType().Name()),
).WithLinks(
	general.NewResourceTypePreprocessor(&aws.AWSCloudControl{}),
	aws.NewAWSCloudControl,
).WithOutputters(
	// output.NewConsoleOutputter,
	output.NewJSONOutputter,
)
