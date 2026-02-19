package gaad

import (
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/aws/iam/orgpolicies"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// analyzerContext holds all state for a single Analyze() invocation.
// Caches are initialized once before concurrent access and are read-only
// during the analysis phase.
type analyzerContext struct {
	gaad        *types.AuthorizationAccountDetails
	orgPolicies *orgpolicies.OrgPolicies
	evaluator   *iam.PolicyEvaluator

	// Read-only caches, initialized once before concurrent access.
	policyCache    map[string]*types.ManagedPolicyDetail
	roleCache      map[string]*types.RoleDetail
	userCache      map[string]*types.UserDetail
	groupCache     map[string]*types.GroupDetail
	resourceCache  map[string]*output.AWSResource
	actionExpander *iam.ActionExpander
}

func newAnalyzerContext(
	gaad *types.AuthorizationAccountDetails,
	orgPolicies *orgpolicies.OrgPolicies,
	resources []output.AWSResource,
) *analyzerContext {
	ctx := &analyzerContext{
		gaad:           gaad,
		orgPolicies:    orgPolicies,
		actionExpander: &iam.ActionExpander{},
	}
	ctx.initializeCaches(resources)

	// Bridge: build PolicyData for the existing PolicyEvaluator.
	// The evaluator reads ResourcePolicies and OrgPolicies during Evaluate().
	resourcePolicies := buildResourcePolicyMap(resources)
	pd := iam.NewPolicyData(gaad, orgPolicies, resourcePolicies, nil)
	ctx.evaluator = iam.NewPolicyEvaluator(pd)

	return ctx
}

// buildResourcePolicyMap extracts typed resource policies from AWSResource inputs
// into the map[arn]*Policy format expected by PolicyEvaluator.
func buildResourcePolicyMap(resources []output.AWSResource) map[string]*types.Policy {
	rp := make(map[string]*types.Policy)
	for i := range resources {
		if resources[i].ResourcePolicy != nil {
			key := resources[i].ARN
			if key == "" {
				key = resources[i].ResourceID
			}
			rp[key] = resources[i].ResourcePolicy
		}
	}
	return rp
}

func (ctx *analyzerContext) initializeCaches(resources []output.AWSResource) {
	gaad := ctx.gaad

	ctx.policyCache = make(map[string]*types.ManagedPolicyDetail, len(gaad.Policies))
	for i := range gaad.Policies {
		ctx.policyCache[gaad.Policies[i].Arn] = &gaad.Policies[i]
	}

	ctx.roleCache = make(map[string]*types.RoleDetail, len(gaad.RoleDetailList))
	for i := range gaad.RoleDetailList {
		ctx.roleCache[gaad.RoleDetailList[i].Arn] = &gaad.RoleDetailList[i]
	}

	ctx.userCache = make(map[string]*types.UserDetail, len(gaad.UserDetailList))
	for i := range gaad.UserDetailList {
		ctx.userCache[gaad.UserDetailList[i].Arn] = &gaad.UserDetailList[i]
	}

	ctx.groupCache = make(map[string]*types.GroupDetail, len(gaad.GroupDetailList))
	for i := range gaad.GroupDetailList {
		ctx.groupCache[gaad.GroupDetailList[i].Arn] = &gaad.GroupDetailList[i]
	}

	// Cloud resources
	estimatedSize := len(resources) + len(gaad.RoleDetailList) + len(gaad.UserDetailList) +
		len(gaad.GroupDetailList) + len(gaad.Policies) + len(commonServicePrincipals) + 1
	ctx.resourceCache = make(map[string]*output.AWSResource, estimatedSize)
	for i := range resources {
		key := resources[i].ARN
		if key == "" {
			key = resources[i].ResourceID
		}
		ctx.resourceCache[key] = &resources[i]
	}

	// IAM entities (overwrite cloud-control versions; GAAD is authoritative for IAM)
	for _, role := range gaad.RoleDetailList {
		ctx.resourceCache[role.Arn] = newAWSResourceFromRole(role)
	}
	for _, user := range gaad.UserDetailList {
		ctx.resourceCache[user.Arn] = newAWSResourceFromUser(user)
	}
	for _, group := range gaad.GroupDetailList {
		ctx.resourceCache[group.Arn] = newAWSResourceFromGroup(group)
	}
	for _, policy := range gaad.Policies {
		ctx.resourceCache[policy.Arn] = newAWSResourceFromPolicy(policy)
	}

	// Common AWS services
	for _, service := range commonServicePrincipals {
		ctx.resourceCache[service] = newAWSResourceFromService(service)
	}

	// Attacker resources (used for cross-account detection)
	ctx.resourceCache["attacker"] = &output.AWSResource{
		Platform:     "aws",
		ResourceType: "AWS::API::Gateway",
		ResourceID:   "attacker",
		ARN:          "attacker",
		Region:       "us-east-1",
		AccountRef:   "123456789012",
	}
}

func (ctx *analyzerContext) getGroupByName(name string) *types.GroupDetail {
	for i := range ctx.gaad.GroupDetailList {
		if ctx.gaad.GroupDetailList[i].GroupName == name {
			return &ctx.gaad.GroupDetailList[i]
		}
	}
	return nil
}

// getResourceDeets returns the account ID and tags for a resource ARN.
func (ctx *analyzerContext) getResourceDeets(resourceArn string) (string, map[string]string) {
	resource, ok := ctx.resourceCache[resourceArn]
	if !ok {
		parsed, err := arn.Parse(resourceArn)
		if err != nil {
			return "", nil
		}
		return parsed.AccountID, nil
	}
	return resource.AccountRef, extractResourceTags(resource)
}
