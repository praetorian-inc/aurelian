package iam

import (
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

// FromUserDL converts a GAAD UserDL to an AWSIAMResource.
func FromUserDL(user UserDL, accountID string) output.AWSIAMResource {
	a, _ := arn.Parse(user.Arn)
	if accountID == "" {
		accountID = a.AccountID
	}

	r := output.AWSIAMResource{
		CloudResource: output.CloudResource{
			Platform:     "aws",
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
		r.PermissionsBoundary = user.PermissionsBoundary
	}
	if len(user.Tags) > 0 {
		r.IAMTags = user.Tags
	}

	return r
}

// FromRoleDL converts a GAAD RoleDL to an AWSIAMResource.
func FromRoleDL(role RoleDL) output.AWSIAMResource {
	a, _ := arn.Parse(role.Arn)

	r := output.AWSIAMResource{
		CloudResource: output.CloudResource{
			Platform:     "aws",
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
		r.PermissionsBoundary = role.PermissionsBoundary
	}
	if len(role.InstanceProfileList) > 0 {
		r.InstanceProfiles = role.InstanceProfileList
	}
	if len(role.Tags) > 0 {
		r.IAMTags = role.Tags
	}

	return r
}

// FromGroupDL converts a GAAD GroupDL to an AWSIAMResource.
func FromGroupDL(group GroupDL) output.AWSIAMResource {
	a, _ := arn.Parse(group.Arn)

	r := output.AWSIAMResource{
		CloudResource: output.CloudResource{
			Platform:     "aws",
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

// FromPolicyDL converts a GAAD PoliciesDL to an AWSIAMResource.
func FromPolicyDL(policy PoliciesDL) output.AWSIAMResource {
	a, _ := arn.Parse(policy.Arn)

	r := output.AWSIAMResource{
		CloudResource: output.CloudResource{
			Platform:     "aws",
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
// Earlier entries win (GAAD entities should be added before CloudResources).
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
