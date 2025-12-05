package aws

import (
	"fmt"
	"log/slog"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type AwsResourcePolicyWithArnFetcher struct {
	*base.AwsReconLink
}

func NewAwsResourcePolicyWithArnFetcher(configs ...cfg.Config) chain.Link {
	r := &AwsResourcePolicyWithArnFetcher{}
	r.AwsReconLink = base.NewAwsReconLink(r, configs...)
	return r
}

func (a *AwsResourcePolicyWithArnFetcher) Process(resource *types.EnrichedResourceDescription) error {
	// Get the policy getter function for this resource type
	policyGetter, ok := ServicePolicyFuncMap[resource.TypeName]
	if !ok {
		// Silently skip resources that don't have resource policies
		slog.Debug("Skipping resource type without resource policy", "type", resource.TypeName)
		return nil
	}

	// Get AWS config from the link parameters
	awsCfg, err := a.GetConfigWithRuntimeArgs(resource.Region)
	if err != nil {
		return fmt.Errorf("failed to get AWS config: %w", err)
	}

	// Get the policy
	policy, err := policyGetter(a.ContextHolder.Context(), awsCfg, resource.Identifier, a.Regions)
	if err != nil {
		slog.Debug("Failed to get policy", "resource", resource.Identifier, "type", resource.TypeName, "error", err)
		return nil // Continue with other resources
	}

	// Skip if no policy
	if policy == nil {
		return nil
	}

	// Create PolicyWithArn wrapper
	policyWithArn := &PolicyWithArn{
		Policy:      policy,
		ResourceArn: resource.Arn.String(),
	}

	// Send the wrapped policy downstream
	a.Send(policyWithArn)
	return nil
}
