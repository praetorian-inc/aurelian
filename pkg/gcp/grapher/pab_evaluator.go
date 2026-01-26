package gcloudiam

import (
	"strings"

	gcptypes "github.com/praetorian-inc/nebula/pkg/types/gcp"
)

type PABMask struct {
	AllowedServices []string
	AllowedPerms    gcptypes.PermissionSet
}

type PABEvaluator struct {
	pabPolicies        []gcptypes.PABPolicy
	pabBindings        []gcptypes.PABBinding
	maskByPrincipalKey map[string]*PABMask
	normalizer         *MemberNormalizer
}

func NewPABEvaluator(pabPolicies []gcptypes.PABPolicy, pabBindings []gcptypes.PABBinding, normalizer *MemberNormalizer) *PABEvaluator {
	return &PABEvaluator{
		pabPolicies:        pabPolicies,
		pabBindings:        pabBindings,
		maskByPrincipalKey: make(map[string]*PABMask),
		normalizer:         normalizer,
	}
}

func (pe *PABEvaluator) BuildPABMasks() {
	policyByName := make(map[string]*gcptypes.PABPolicy)
	for i := range pe.pabPolicies {
		policyByName[pe.pabPolicies[i].Name] = &pe.pabPolicies[i]
	}
	for _, binding := range pe.pabBindings {
		policy, ok := policyByName[binding.PolicyName]
		if !ok {
			continue
		}
		mask := pe.buildMaskFromPolicy(policy)
		principal := pe.normalizer.NormalizeMember(binding.PrincipalSetURI)
		principalKey := pe.normalizer.GetResourceKey(principal)
		pe.maskByPrincipalKey[principalKey] = mask
	}
}

func (pe *PABEvaluator) buildMaskFromPolicy(policy *gcptypes.PABPolicy) *PABMask {
	mask := &PABMask{
		AllowedServices: make([]string, 0),
		AllowedPerms:    gcptypes.NewPermissionSet(),
	}
	for _, rule := range policy.Rules {
		for _, resource := range rule.Resources {
			if strings.Contains(resource, ".") {
				mask.AllowedPerms.Add(gcptypes.Permission(resource))
			} else {
				mask.AllowedServices = append(mask.AllowedServices, resource)
			}
		}
	}
	return mask
}

func (pe *PABEvaluator) isPermissionAllowed(perm gcptypes.Permission, mask *PABMask) bool {
	if mask.AllowedPerms.Contains(perm) {
		return true
	}
	permStr := string(perm)
	for _, service := range mask.AllowedServices {
		if strings.HasPrefix(permStr, service+".") {
			return true
		}
	}
	return false
}
