package aws

import (
	"log/slog"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/janus/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/links/general"
)

type AWSFindSecrets struct {
	*AwsReconLink
}

func NewAWSFindSecrets(configs ...cfg.Config) chain.Link {
	fs := &AWSFindSecrets{}
	// Initialize the embedded AwsReconLink with fs as the link
	fs.AwsReconLink = NewAwsReconLink(fs, configs...)
	return fs
}

func (a *AWSFindSecrets) Process(resource *types.EnrichedResourceDescription) error {
	var resourceChain chain.Chain
	var err error

	switch resource.TypeName {
	case "AWS::EC2::Instance":
		resourceChain = chain.NewChain(
			NewAWSEC2UserData(),
			general.NewErdToNPInput(),
		)

	case "AWS::Lambda::Function":
		resourceChain = chain.NewChain(
			general.NewErdToNPInput(),
		)

	// case "AWS::CloudFormation::Stack":
	// 	resourceChain = chain.NewChain(
	// 		NewAWSCloudFormationTemplates(),
	// 	)
	default:
		slog.Error("Unsupported resource type", "resource", resource)
		return nil
	}

	if err != nil {
		slog.Error("Failed to start resource chain", "error", err)
		return nil
	}

	ccArgs := make(map[string]any)
	for _, param := range a.Params() {
		name := param.Name()
		if a.HasParam(name) {
			ccArgs[name] = a.Arg(name)
		}
	}

	// propogate the args to the chain
	resourceChain = resourceChain.WithConfigs(cfg.WithArgs(ccArgs))
	resourceChain.Send(resource)
	resourceChain.Close()

	for o, ok := chain.RecvAs[types.NPInput](resourceChain); ok; o, ok = chain.RecvAs[types.NPInput](resourceChain) {
		a.Send(o)
	}

	return nil
}
