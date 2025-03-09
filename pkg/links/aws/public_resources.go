package aws

import (
	"log/slog"
	"strings"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/general"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

// PublicTypes contains the list of AWS resource types that can have public exposure
var PublicTypes = []string{
	"AWS::EC2::Instance",
}

type AwsPublicResources struct {
	*AwsReconLink
}

func NewAwsPublicResources(configs ...cfg.Config) chain.Link {
	a := &AwsPublicResources{}
	// Initialize the embedded AwsReconLink with fs as the link
	a.AwsReconLink = NewAwsReconLink(a, configs...)
	return a
}

func (a *AwsPublicResources) Params() []cfg.Param {
	params := a.AwsReconLink.Params()
	params = append(params, options.AwsCommonReconOptions()...)
	params = append(params, options.AwsRegions(), options.AwsResourceType())
	return params
}

func (a *AwsPublicResources) Process(resourceType string) error {
	if strings.EqualFold(resourceType, "all") {
		slog.Info("Listing all public resource types")
		for _, rtype := range PublicTypes {
			a.processResourceType(rtype)
		}
		return nil
	}

	return a.processResourceType(resourceType)
}

func (a *AwsPublicResources) processResourceType(resourceType string) error {
	var resourceChain chain.Chain

	// Build different resource chains based on resource type
	switch resourceType {
	case "AWS::EC2::Instance":
		resourceChain = chain.NewChain(
			NewAWSCloudControl(),
			general.NewJqFilter(cfg.WithArg("filter", "select(.Properties | fromjson | has(\"PublicIp\")) | {Type: .TypeName, Identifier: .Identifier, PublicIp: (.Properties | fromjson | .PublicIp)}")),
		)
	default:
		slog.Error("Unsupported resource type", "resourceType", resourceType)
	}

	// Propagate parameters from this link to the chain
	ccArgs := make(map[string]any)
	for k, v := range a.Args() {
		ccArgs[k] = v
	}

	resourceChain = resourceChain.WithConfigs(cfg.WithArgs(ccArgs))
	resourceChain.Send(resourceType)
	resourceChain.Close()

	// Collect and forward results
	for result, ok := chain.RecvAs[map[string]interface{}](resourceChain); ok; result, ok = chain.RecvAs[map[string]interface{}](resourceChain) {
		a.Send(result)
	}

	return resourceChain.Error()
}
