//go:build aws || aws_recon || aws_recon_find_secrets || all

package recon

import (
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/janus/pkg/output"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/aws"
)

func init() {
	registry.Register("aws", "recon", "find-secrets", *AWSFindSecrets)
}

// List of resource types to scan for secrets
var FindSecretsTypes = []string{
	"AWS::EC2::Instance",
	"AWS::CloudFormation::Stack",
}

var AWSFindSecrets = chain.NewModule(
	cfg.NewMetadata(
		"AWS Find Secrets",
		"Enumerate AWS resources and find secrets using NoseyParker",
	).WithProperty(
		"platform", "aws",
	).WithProperty(
		"opsec_level", "moderate",
	).WithProperty(
		"authors", []string{"Praetorian"},
	),
	chain.NewChain(
		aws.NewAWSCloudControl(),
	).WithOutputters(
		output.NewJSONOutputter(),
		output.NewConsoleOutputter(),
	),
)
