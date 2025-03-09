package aws

import (
	"log/slog"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/janus/pkg/links/docker"
	"github.com/praetorian-inc/janus/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/links/aws/cloudformation"
	"github.com/praetorian-inc/nebula/pkg/links/aws/ec2"
	"github.com/praetorian-inc/nebula/pkg/links/aws/ecr"
	"github.com/praetorian-inc/nebula/pkg/links/aws/lambda"
	"github.com/praetorian-inc/nebula/pkg/links/general"
)

type AWSFindSecrets struct {
	*base.AwsReconLink
	clientMap map[string]interface{} // map key is type-region
}

func NewAWSFindSecrets(configs ...cfg.Config) chain.Link {
	fs := &AWSFindSecrets{}
	// Initialize the embedded AwsReconLink with fs as the link
	fs.AwsReconLink = base.NewAwsReconLink(fs, configs...)
	return fs
}

func (a *AWSFindSecrets) Process(resource *types.EnrichedResourceDescription) error {
	var resourceChain chain.Chain

	slog.Debug("Processing resource", "resource", resource)

	switch resource.TypeName {
	case "AWS::EC2::Instance":
		resourceChain = chain.NewChain(
			ec2.NewAWSEC2UserData(),
		)

	case "AWS::Lambda::Function":
		resourceChain = chain.NewMulti(
			general.NewErdToNPInput(),
			lambda.NewAWSLambdaFunctionCode(),
		)

	case "AWS::CloudFormation::Stack":
		resourceChain = chain.NewChain(
			cloudformation.NewAWSCloudFormationTemplates(),
		)

	case "AWS::ECR::Repository":
		resourceChain = chain.NewChain(
			ecr.NewAWSECRListImages(),
			ecr.NewAWSECRLogin(),
			docker.NewDockerPull(),
		)

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
		slog.Debug("NPInput", "npinput", o)
		a.Send(o)
	}

	return resourceChain.Error()
}
