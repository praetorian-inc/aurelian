package aws

import (
	"log/slog"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/links/aws/cloudcontrol"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AwsPublicResources struct {
	*base.AwsReconLink
	resourceMap map[string]func() chain.Chain
}

func NewAwsPublicResources(configs ...cfg.Config) chain.Link {
	a := &AwsPublicResources{}
	// Initialize the embedded AwsReconLink with fs as the link
	a.AwsReconLink = base.NewAwsReconLink(a, configs...)
	return a
}

func (a *AwsPublicResources) Params() []cfg.Param {
	params := a.AwsReconLink.Params()
	params = append(params, options.AwsCommonReconOptions()...)
	params = append(params, options.AwsRegions(), options.AwsResourceType())
	return params
}

func (a *AwsPublicResources) Initialize() error {
	if err := a.AwsReconLink.Initialize(); err != nil {
		return err
	}

	a.resourceMap = a.ResourceMap()
	return nil
}

func (a *AwsPublicResources) Process(resource *types.EnrichedResourceDescription) error {
	rc, ok := a.resourceMap[resource.TypeName]
	if !ok {
		slog.Error("Unsupported resource type", "resourceType", resource.Type)
		return nil
	}

	c := rc()
	c.WithConfigs(cfg.WithArgs(a.Args()))

	c.Send(resource)
	c.Close()

	for o, ok := chain.RecvAs[*types.EnrichedResourceDescription](c); ok; o, ok = chain.RecvAs[*types.EnrichedResourceDescription](c) {
		a.Send(o)
	}

	if err := c.Error(); err != nil {
		slog.Error("Error processing resource for public resources", "resource", resource, "error", err)
	}

	return nil

}

func (a *AwsPublicResources) SupportedResourceTypes() []string {
	resources := a.ResourceMap()
	types := make([]string, 0, len(resources))
	for resourceType := range resources {
		types = append(types, resourceType)
	}
	return types
}

func (a *AwsPublicResources) ResourceMap() map[string]func() chain.Chain {
	resourceMap := make(map[string]func() chain.Chain)

	resourceMap["AWS::EC2::Instance"] = func() chain.Chain {
		return chain.NewChain(
			cloudcontrol.NewCloudControlGet(),
			NewPropertyFilterLink(cfg.WithArg("property", "PublicIp")),
		)
	}

	resourceMap["AWS::SNS::Topic"] = func() chain.Chain {
		return chain.NewChain(
			cloudcontrol.NewCloudControlGet(),
			NewAwsResourcePolicyChecker(),
		)
	}

	resourceMap["AWS::SQS::Queue"] = func() chain.Chain {
		return chain.NewChain(
			cloudcontrol.NewCloudControlGet(),
			NewAwsResourcePolicyChecker(),
		)
	}

	resourceMap["AWS::Lambda::Function"] = func() chain.Chain {
		return chain.NewChain(
			cloudcontrol.NewCloudControlGet(),
			NewAwsResourcePolicyChecker(),
		)
	}

	resourceMap["AWS::EFS::FileSystem"] = func() chain.Chain {
		return chain.NewChain(
			cloudcontrol.NewCloudControlGet(),
			NewAwsResourcePolicyChecker(),
		)
	}

	// resourceMap["AWS::Elasticsearch::Domain"] = func() chain.Chain {
	// 	return chain.NewChain(
	// 		NewAwsResourcePolicyChecker(),
	// 	)
	// }

	resourceMap["AWS::S3::Bucket"] = func() chain.Chain {
		return chain.NewChain(
			cloudcontrol.NewCloudControlGet(),
			NewAwsResourcePolicyChecker(),
		)
	}

	resourceMap["AWS::RDS::DBInstance"] = func() chain.Chain {
		return chain.NewChain(
			cloudcontrol.NewCloudControlGet(),
			NewPropertyFilterLink(cfg.WithArg("property", "PubliclyAccessible")),
		)
	}

	return resourceMap
}
