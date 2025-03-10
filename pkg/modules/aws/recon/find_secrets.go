package recon

import (
	"strings"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	jlinks "github.com/praetorian-inc/janus/pkg/links"
	"github.com/praetorian-inc/janus/pkg/links/noseyparker"
	"github.com/praetorian-inc/janus/pkg/output"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

func init() {
	registry.Register("aws", "recon", "find-secrets", *AWSFindSecrets)
}

func preprocessResourceTypes(self chain.Link, resourceType string) error {
	resourceTypes := []string{resourceType}

	if strings.ToLower(resourceType) == "all" {
		resourceTypes = (&aws.AWSFindSecrets{}).SupportedResourceTypes()
	}

	for _, resourceType := range resourceTypes {
		self.Send(resourceType)
	}

	return nil
}

var AWSFindSecrets = chain.NewModule(
	cfg.NewMetadata(
		"AWS Find Secrets",
		"Enumerate AWS resources and find secrets using NoseyParker",
	).WithProperties(map[string]any{
		"platform":    "aws",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
	}).WithChainInputParam(options.AwsResourceType().Name()),
	chain.NewChain(
		jlinks.NewAdHocLink(preprocessResourceTypes),
		aws.NewAWSCloudControl(),
		aws.NewAWSFindSecrets(),
		noseyparker.NewNoseyParkerScanner(cfg.WithArg("continue_piping", true)),
	).WithOutputters(
		output.NewJSONOutputter(),
		output.NewConsoleOutputter(),
	).WithParams(
		options.AwsResourceType().WithDefault([]string{"all"}),
	),
)
