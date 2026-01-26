package gcloudcollectors

import (
	"context"
	"fmt"

	iamv3 "cloud.google.com/go/iam/apiv3"
	iamv3pb "cloud.google.com/go/iam/apiv3/iampb"
	gcptypes "github.com/praetorian-inc/nebula/pkg/types/gcp"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

type PABCollector struct {
	ctx               context.Context
	clientOptions     []option.ClientOption
	pabPoliciesClient *iamv3.PrincipalAccessBoundaryPoliciesClient
	pabBindingsClient *iamv3.PolicyBindingsClient
}

func NewPABCollector(ctx context.Context, clientOptions ...option.ClientOption) (*PABCollector, error) {
	collector := &PABCollector{
		ctx:           ctx,
		clientOptions: clientOptions,
	}
	var err error
	collector.pabPoliciesClient, err = iamv3.NewPrincipalAccessBoundaryPoliciesClient(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create PAB policies client: %w", err)
	}
	collector.pabBindingsClient, err = iamv3.NewPolicyBindingsClient(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create PAB bindings client: %w", err)
	}
	return collector, nil
}

func (pc *PABCollector) Close() error {
	var errs []error
	if pc.pabPoliciesClient != nil {
		if err := pc.pabPoliciesClient.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if pc.pabBindingsClient != nil {
		if err := pc.pabBindingsClient.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("errors closing clients: %v", errs)
	}
	return nil
}

func (pc *PABCollector) CollectPABPolicies(orgID string) ([]gcptypes.PABPolicy, error) {
	parent := fmt.Sprintf("organizations/%s/locations/global", extractIDFromURI(orgID))
	req := &iamv3pb.ListPrincipalAccessBoundaryPoliciesRequest{
		Parent: parent,
	}
	it := pc.pabPoliciesClient.ListPrincipalAccessBoundaryPolicies(pc.ctx, req)
	pabPolicies := make([]gcptypes.PABPolicy, 0)
	for {
		policy, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list PAB policies: %w", err)
		}
		pabPolicy := gcptypes.PABPolicy{
			Name:        policy.Name,
			DisplayName: policy.DisplayName,
			Rules:       make([]gcptypes.PABRule, 0),
		}
		if policy.Details != nil {
			pabPolicy.EnforcementVersion = policy.Details.EnforcementVersion
			for _, rule := range policy.Details.Rules {
				pabRule := gcptypes.PABRule{
					Description: rule.Description,
					Resources:   rule.Resources,
				}
				pabPolicy.Rules = append(pabPolicy.Rules, pabRule)
			}
		}
		pabPolicies = append(pabPolicies, pabPolicy)
	}
	return pabPolicies, nil
}

func (pc *PABCollector) CollectPABBindings(containerURI string) ([]gcptypes.PABBinding, error) {
	parent := fmt.Sprintf("%s/locations/global", containerURI)
	req := &iamv3pb.ListPolicyBindingsRequest{
		Parent: parent,
	}
	it := pc.pabBindingsClient.ListPolicyBindings(pc.ctx, req)
	pabBindings := make([]gcptypes.PABBinding, 0)
	for {
		binding, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to list policy bindings: %w", err)
		}
		if binding.PolicyKind != iamv3pb.PolicyBinding_PRINCIPAL_ACCESS_BOUNDARY { // skip if kind is unspecified; just safety
			continue
		}
		pabBinding := gcptypes.PABBinding{
			Name:       binding.Name,
			PolicyName: binding.Policy,
			ParentURI:  containerURI,
		}
		if binding.Target != nil {
			principalSet := binding.Target.GetPrincipalSet()
			if principalSet != "" {
				pabBinding.PrincipalSetURI = principalSet
			}
		}
		if binding.Condition != nil {
			pabBinding.Condition = &gcptypes.Condition{
				Title:       binding.Condition.Title,
				Description: binding.Condition.Description,
				Expression:  binding.Condition.Expression,
			}
		}
		pabBindings = append(pabBindings, pabBinding)
	}
	return pabBindings, nil
}
