package recon

import (
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	jlinks "github.com/praetorian-inc/janus/pkg/links"
	"github.com/praetorian-inc/janus/pkg/output"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws"
	"github.com/praetorian-inc/nebula/pkg/links/general"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

func init() {
	registry.Register("aws", "recon", "public-resources", *AWSPublicResources)
}

var preprocessor = general.PreprocessResourceTypes(&aws.AwsPublicResources{})

var AWSPublicResources = chain.NewModule(
	cfg.NewMetadata(
		"AWS Public Resources",
		"Enumerate public AWS resources",
	).WithProperties(map[string]any{
		"platform":    "aws",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
	}).
		WithChainInputParam(options.AwsResourceType().Name()),
).WithLinks(
	jlinks.ConstructAdHocLink(preprocessor),
	aws.NewAwsPublicResources,
).WithOutputters(
	output.NewJSONOutputter,
	output.NewConsoleOutputter,
)
