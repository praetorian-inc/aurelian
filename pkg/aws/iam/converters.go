package iam

import (
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// FromUserDL converts a GAAD UserDetail to an AWSIAMResource.
func FromUserDL(user types.UserDetail, accountID string) output.AWSIAMResource {
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

// FromRoleDL converts a GAAD RoleDetail to an AWSIAMResource.
func FromRoleDL(role types.RoleDetail) output.AWSIAMResource {
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

// FromGroupDL converts a GAAD GroupDetail to an AWSIAMResource.
func FromGroupDL(group types.GroupDetail) output.AWSIAMResource {
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

// FromPolicyDL converts a GAAD ManagedPolicyDetail to an AWSIAMResource.
func FromPolicyDL(policy types.ManagedPolicyDetail) output.AWSIAMResource {
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

// FromGAAD converts all GAAD entities to AWSIAMResources.
// The accountID is passed to FromUserDL for user account resolution.
func FromGAAD(gaad *Gaad, accountID string) []output.AWSIAMResource {
	var entities []output.AWSIAMResource
	for _, user := range gaad.UserDetailList {
		entities = append(entities, FromUserDL(user, accountID))
	}
	for _, role := range gaad.RoleDetailList {
		entities = append(entities, FromRoleDL(role))
	}
	for _, group := range gaad.GroupDetailList {
		entities = append(entities, FromGroupDL(group))
	}
	for _, policy := range gaad.Policies {
		entities = append(entities, FromPolicyDL(policy))
	}
	return entities
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

