package recon

import (
	"strings"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	jlinks "github.com/praetorian-inc/janus/pkg/links"
	"github.com/praetorian-inc/janus/pkg/output"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

func init() {
	registry.Register("aws", "recon", "public-resources", *AWSPublicResources)
}

func getPublicResourceTypes(self chain.Link, resourceType string) error {
	resourceTypes := []string{resourceType}

	if strings.ToLower(resourceType) == "all" {
		resourceTypes = (&aws.AwsPublicResources{}).SupportedResourceTypes()
	}

	for _, resourceType := range resourceTypes {
		self.Send(resourceType)
	}

	return nil
}

var AWSPublicResources = chain.NewModule(
	cfg.NewMetadata(
		"AWS Public Resources",
		"Enumerate public AWS resources",
	).WithProperty(
		"platform", "aws",
	).WithProperty(
		"opsec_level", "moderate",
	).WithProperty(
		"authors", []string{"Praetorian"},
	).WithChainInputParam(options.AwsResourceType().Name()),
).WithLinks(
	jlinks.ConstructAdHocLink(getPublicResourceTypes),
	aws.NewAwsPublicResources,
).WithOutputters(
	output.NewJSONOutputter,
	output.NewConsoleOutputter,
)
