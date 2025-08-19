package aws

import (
	"fmt"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/links/aws/cloudcontrol"
	"github.com/praetorian-inc/nebula/pkg/links/general"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// PolicyWithArn wraps a policy with its associated resource ARN for keying
type PolicyWithArn struct {
	Policy     *types.Policy `json:"policy"`
	ResourceArn string       `json:"resource_arn"`
}

type AwsResourcePolicyCollector struct {
	*base.AwsReconLink
}

func NewAwsResourcePolicyCollector(configs ...cfg.Config) chain.Link {
	r := &AwsResourcePolicyCollector{}
	r.AwsReconLink = base.NewAwsReconLink(r, configs...)
	return r
}

func (a *AwsResourcePolicyCollector) SupportedResourceTypes() []string {
	// Return resource types that have resource policies
	return []string{
		"AWS::S3::Bucket",
		"AWS::SNS::Topic", 
		"AWS::SQS::Queue",
		"AWS::Lambda::Function",
		"AWS::EFS::FileSystem",
		"AWS::ElasticSearch::Domain",
	}
}

func (a *AwsResourcePolicyCollector) Params() []cfg.Param {
	params := a.AwsReconLink.Params()
	params = append(params, options.AwsCommonReconOptions()...)
	return params
}

func (a *AwsResourcePolicyCollector) Process(resourceType string) error {
	a.Logger.Debug(fmt.Sprintf("Processing resource type: %s", resourceType))
	a.Logger.Debug(fmt.Sprintf("Supported resource types: %v", a.SupportedResourceTypes()))
	
	// First, gather all resources
	resourceChain := chain.NewChain(
		general.NewResourceTypePreprocessor(a)(),
		cloudcontrol.NewAWSCloudControl(cfg.WithArgs(a.Args())),
	)

	resourceChain.WithConfigs(cfg.WithArgs(a.Args()))
	resourceChain.Send(resourceType)
	resourceChain.Close()

	// Collect resources 
	var resources []types.EnrichedResourceDescription
	for {
		resource, ok := chain.RecvAs[*types.EnrichedResourceDescription](resourceChain)
		if !ok {
			break
		}
		a.Logger.Debug(fmt.Sprintf("Received resource: %s (type: %s)", resource.Arn.String(), resource.TypeName))
		resources = append(resources, *resource)
	}
	resourceChain.Wait()

	a.Logger.Info(fmt.Sprintf("Found %d resources to check for policies", len(resources)))
	
	// Debug: log all resource ARNs and types
	for i, res := range resources {
		a.Logger.Debug(fmt.Sprintf("Resource %d: ARN=%s, Type=%s", i, res.Arn.String(), res.TypeName))
	}

	// Now collect policies for each resource
	policyMap := make(map[string]*types.Policy)

	for _, resource := range resources {
		a.Logger.Debug(fmt.Sprintf("Processing resource %s (type: %s) for policies", resource.Arn.String(), resource.TypeName))
		
		// Create policy fetcher chain for this resource
		policyChain := chain.NewChain(
			NewAwsResourcePolicyFetcher(cfg.WithArgs(a.Args())),
		)
		policyChain.WithConfigs(cfg.WithArgs(a.Args()))
		
		policyChain.Send(resource)
		policyChain.Close()

		// Collect policy from this resource
		policyFound := false
		for {
			policy, ok := chain.RecvAs[*types.Policy](policyChain)
			if !ok {
				break
			}
			if policy != nil {
				policyMap[resource.Arn.String()] = policy
				a.Logger.Debug(fmt.Sprintf("Collected policy for resource %s", resource.Arn.String()))
				policyFound = true
			}
		}
		
		if !policyFound {
			a.Logger.Debug(fmt.Sprintf("No policy found for resource %s (type: %s)", resource.Arn.String(), resource.TypeName))
		}
		
		policyChain.Wait()
	}

	a.Logger.Info(fmt.Sprintf("Collected %d resource policies", len(policyMap)))

	// Send the complete policy map to outputter
	a.Send(policyMap)
	return nil
}