package aws

import (
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/janus/pkg/links/docker"
	jtypes "github.com/praetorian-inc/janus/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/links/aws/cloudformation"
	"github.com/praetorian-inc/nebula/pkg/links/aws/ec2"
	"github.com/praetorian-inc/nebula/pkg/links/aws/ecr"
	"github.com/praetorian-inc/nebula/pkg/links/aws/lambda"
	"github.com/praetorian-inc/nebula/pkg/links/general"
	"github.com/praetorian-inc/nebula/pkg/types"
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
	var links []chain.Link

	slog.Debug("Processing resource", "resource", resource)

	switch resource.TypeName {
	case "AWS::EC2::Instance":
		links = []chain.Link{
			ec2.NewAWSEC2UserData(),
		}

	case "AWS::Lambda::Function":
		links = []chain.Link{
			chain.NewMulti(
				general.NewToNPInput(),
				lambda.NewAWSLambdaFunctionCode(),
			),
		}

	case "AWS::CloudFormation::Stack":
		links = []chain.Link{
			cloudformation.NewAWSCloudFormationTemplates(),
		}

	case "AWS::ECR::Repository":
		links = []chain.Link{
			ecr.NewAWSECRListImages(),
			ecr.NewAWSECRLogin(),
			docker.NewDockerPull(),
			docker.NewDockerSave(),
			general.NewToNPInput(),
		}

	case "AWS::ECR::PublicRepository":
		links = []chain.Link{
			ecr.NewAWSECRListPublicImages(),
			ecr.NewAWSECRLoginPublic(),
			docker.NewDockerPull(),
			docker.NewDockerSave(),
			general.NewToNPInput(),
		}

	case "AWS::ECS::TaskDefinition":
		links = []chain.Link{
			general.NewToNPInput(),
		}

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

	resourceChain := chain.NewChain(links...)

	resourceChain.WithConfigs(cfg.WithArgs(ccArgs))
	resourceChain.WithParams(a.Params()...)

	slog.Debug("Sending resource to chain", "resource", resource, "type", fmt.Sprintf("%T", resource))
	resourceChain.Send(resource)
	resourceChain.Close()

	for o, ok := chain.RecvAs[jtypes.NPInput](resourceChain); ok; o, ok = chain.RecvAs[jtypes.NPInput](resourceChain) {
		slog.Debug("NPInput", "npinput", o)
		a.Send(o)
	}

	return resourceChain.Error()
}
