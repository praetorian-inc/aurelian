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
	clientMap map[string]interface{} // map key is type-region
}

func NewAWSFindSecrets(configs ...cfg.Config) chain.Link {
	fs := &AWSFindSecrets{}
	// Initialize the embedded AwsReconLink with fs as the link
	fs.AwsReconLink = NewAwsReconLink(fs, configs...)
	return fs
}

func (a *AWSFindSecrets) Process(resource *types.EnrichedResourceDescription) error {
	var resourceChain chain.Chain

	slog.Debug("Processing resource", "resource", resource)

	switch resource.TypeName {
	case "AWS::EC2::Instance":
		resourceChain = chain.NewChain(
			NewAWSEC2UserData(),
		)

	case "AWS::Lambda::Function":
		resourceChain = chain.NewMulti(
			general.NewErdToNPInput(),
			NewAWSLambdaFunctionCode(),
		)

	case "AWS::CloudFormation::Stack":
		resourceChain = chain.NewChain(
			NewAWSCloudFormationTemplates(),
		)

	case "AWS::ECR::Repository":
		
	default:
		slog.Error("Unsupported resource type", "resource", resource)
		return nil
	}

	ccArgs := make(map[string]any)
	for _, param := range a.Params() {
		name := param.Name()
		if a.HasParam(name) {
			ccArgs[name] = a.Arg(name)
		}
	}

	resourceChain.WithConfigs(cfg.WithArgs(ccArgs))
	resourceChain.WithParams(a.Params()...)

	resourceChain.Send(resource)
	resourceChain.Close()

	for o, ok := chain.RecvAs[types.NPInput](resourceChain); ok; o, ok = chain.RecvAs[types.NPInput](resourceChain) {
		a.Send(o)
	}

	return resourceChain.Error()
}
