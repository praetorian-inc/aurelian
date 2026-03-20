package gaad

import (
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/store"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// ---------------------------------------------------------------------------
// IAM entity → output.AWSResource converters
// ---------------------------------------------------------------------------

func newAWSResourceFromRole(role types.RoleDetail) *output.AWSResource {
	a, _ := arn.Parse(role.Arn)
	return &output.AWSResource{
		ResourceType: "AWS::IAM::Role",
		ResourceID:   role.Arn,
		ARN:          role.Arn,
		AccountRef:   a.AccountID,
		DisplayName:  role.RoleName,
	}
}

func newAWSResourceFromUser(user types.UserDetail) *output.AWSResource {
	a, _ := arn.Parse(user.Arn)
	return &output.AWSResource{
		ResourceType: "AWS::IAM::User",
		ResourceID:   user.Arn,
		ARN:          user.Arn,
		AccountRef:   a.AccountID,
		DisplayName:  user.UserName,
	}
}

func newAWSResourceFromGroup(group types.GroupDetail) *output.AWSResource {
	a, _ := arn.Parse(group.Arn)
	return &output.AWSResource{
		ResourceType: "AWS::IAM::Group",
		ResourceID:   group.Arn,
		ARN:          group.Arn,
		AccountRef:   a.AccountID,
		DisplayName:  group.GroupName,
	}
}

func newAWSResourceFromPolicy(policy types.ManagedPolicyDetail) *output.AWSResource {
	a, _ := arn.Parse(policy.Arn)
	return &output.AWSResource{
		ResourceType: "AWS::IAM::ManagedPolicy",
		ResourceID:   policy.Arn,
		ARN:          policy.Arn,
		AccountRef:   a.AccountID,
		DisplayName:  policy.PolicyName,
	}
}

// extractResourceTags extracts tags from an AWSResource's Properties map.
// CloudControl resources store tags as Properties["Tags"] = []{Key:..., Value:...}.
// IAM resources created from GAAD have no Properties, so this returns empty.
func extractResourceTags(r *output.AWSResource) map[string]string {
	if r == nil || r.Properties == nil {
		return map[string]string{}
	}
	tags, ok := r.Properties["Tags"]
	if !ok {
		return map[string]string{}
	}
	tagList, ok := tags.([]any)
	if !ok {
		return map[string]string{}
	}
	result := make(map[string]string, len(tagList))
	for _, t := range tagList {
		tag, ok := t.(map[string]any)
		if !ok {
			continue
		}
		key, _ := tag["Key"].(string)
		value, _ := tag["Value"].(string)
		if key != "" {
			result[key] = value
		}
	}
	return result
}

// ---------------------------------------------------------------------------
// GAAD entity → output.AWSIAMResource converters
// ---------------------------------------------------------------------------

// FromUserDetail converts a GAAD UserDetail to an AWSIAMResource.
func FromUserDetail(user types.UserDetail, accountID string) output.AWSIAMResource {
	a, _ := arn.Parse(user.Arn)
	if accountID == "" {
		accountID = a.AccountID
	}

	r := output.AWSIAMResource{
		AWSResource: output.AWSResource{
			ResourceType: "AWS::IAM::User",
			ResourceID:   user.Arn,
			ARN:          user.Arn,
			AccountRef:   accountID,
			DisplayName:  user.UserName,
		},
		GroupMemberships: user.GroupList,
		OriginalData:     user,
	}

	if len(user.UserPolicyList) > 0 {
		r.InlinePolicies = user.UserPolicyList
	}
	if len(user.AttachedManagedPolicies) > 0 {
		r.AttachedManagedPolicies = user.AttachedManagedPolicies
	}
	if user.PermissionsBoundary.PolicyArn != "" {
		r.PermissionsBoundary = &user.PermissionsBoundary
	}
	if len(user.Tags) > 0 {
		r.IAMTags = user.Tags
	}

	return r
}

// FromRoleDetail converts a GAAD RoleDetail to an AWSIAMResource.
func FromRoleDetail(role types.RoleDetail) output.AWSIAMResource {
	a, _ := arn.Parse(role.Arn)

	r := output.AWSIAMResource{
		AWSResource: output.AWSResource{
			ResourceType: "AWS::IAM::Role",
			ResourceID:   role.Arn,
			ARN:          role.Arn,
			AccountRef:   a.AccountID,
			DisplayName:  role.RoleName,
		},
		AssumeRolePolicy: &role.AssumeRolePolicyDocument,
		OriginalData:     role,
	}

	if len(role.RolePolicyList) > 0 {
		r.InlinePolicies = role.RolePolicyList
	}
	if len(role.AttachedManagedPolicies) > 0 {
		r.AttachedManagedPolicies = role.AttachedManagedPolicies
	}
	if role.PermissionsBoundary.PolicyArn != "" {
		r.PermissionsBoundary = &role.PermissionsBoundary
	}
	if len(role.InstanceProfileList) > 0 {
		r.InstanceProfiles = role.InstanceProfileList
	}
	if len(role.Tags) > 0 {
		r.IAMTags = role.Tags
	}

	return r
}

// FromGroupDetail converts a GAAD GroupDetail to an AWSIAMResource.
func FromGroupDetail(group types.GroupDetail) output.AWSIAMResource {
	a, _ := arn.Parse(group.Arn)

	r := output.AWSIAMResource{
		AWSResource: output.AWSResource{
			ResourceType: "AWS::IAM::Group",
			ResourceID:   group.Arn,
			ARN:          group.Arn,
			AccountRef:   a.AccountID,
			DisplayName:  group.GroupName,
		},
		OriginalData: group,
	}

	if len(group.GroupPolicyList) > 0 {
		r.InlinePolicies = group.GroupPolicyList
	}
	if len(group.AttachedManagedPolicies) > 0 {
		r.AttachedManagedPolicies = group.AttachedManagedPolicies
	}

	return r
}

// FromManagedPolicyDetail converts a GAAD ManagedPolicyDetail to an AWSIAMResource.
func FromManagedPolicyDetail(policy types.ManagedPolicyDetail) output.AWSIAMResource {
	a, _ := arn.Parse(policy.Arn)

	r := output.AWSIAMResource{
		AWSResource: output.AWSResource{
			ResourceType: "AWS::IAM::ManagedPolicy",
			ResourceID:   policy.Arn,
			ARN:          policy.Arn,
			AccountRef:   a.AccountID,
			DisplayName:  policy.PolicyName,
		},
		OriginalData: policy,
	}

	if len(policy.PolicyVersionList) > 0 {
		r.PolicyVersions = policy.PolicyVersionList
	}

	return r
}

// DeduplicateByARN deduplicates AWSIAMResources by ARN.
// Earlier entries win (GAAD entities should be added before AWSResources).
func DeduplicateByARN(entities []output.AWSIAMResource) []output.AWSIAMResource {
	seen := make(map[string]bool, len(entities))
	result := make([]output.AWSIAMResource, 0, len(entities))

	for _, e := range entities {
		key := e.ARN
		if key == "" {
			key = e.ResourceID
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, e)
	}

	return result
}

// EmitGAADEntities iterates all GAAD entity maps (users, roles, groups, policies),
// converts each to an AWSIAMResource, and calls emit for entities with unseen ARNs.
// The seen map is used for deduplication and can be shared across calls.
func EmitGAADEntities(gaad *types.AuthorizationAccountDetails, accountID string, emit func(output.AWSIAMResource)) {
	seen := store.NewMap[string]()
	emitOnce := func(entity output.AWSIAMResource) {
		key := entity.ARN
		if key == "" {
			key = entity.ResourceID
		}

		if _, ok := seen.Get(key); ok {
			return
		}

		seen.Set(key, key)
		emit(entity)
	}

	gaad.Users.Range(func(_ string, user types.UserDetail) bool {
		emitOnce(FromUserDetail(user, accountID))
		return true
	})
	gaad.Roles.Range(func(_ string, role types.RoleDetail) bool {
		emitOnce(FromRoleDetail(role))
		return true
	})
	gaad.Groups.Range(func(_ string, group types.GroupDetail) bool {
		emitOnce(FromGroupDetail(group))
		return true
	})
	gaad.Policies.Range(func(_ string, policy types.ManagedPolicyDetail) bool {
		emitOnce(FromManagedPolicyDetail(policy))
		return true
	})
}
