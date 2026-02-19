package iam

import (
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func NewEnrichedResourceDescriptionFromRoleDL(roleDL RoleDetail) *types.EnrichedResourceDescription {
	a, _ := arn.Parse(roleDL.Arn)

	return &types.EnrichedResourceDescription{
		Identifier: roleDL.RoleName,
		TypeName:   "AWS::IAM::Role",
		Region:     "",
		AccountId:  a.AccountID,
		Arn:        a,
	}
}

func NewEnrichedResourceDescriptionFromPolicyDL(policyDL ManagedPolicyDetail) *types.EnrichedResourceDescription {
	a, _ := arn.Parse(policyDL.Arn)

	return &types.EnrichedResourceDescription{
		Identifier: policyDL.PolicyName,
		TypeName:   "AWS::IAM::ManagedPolicy",
		Region:     "",
		AccountId:  a.AccountID,
		Arn:        a,
	}
}

func NewEnrichedResourceDescriptionFromUserDL(userDL UserDetail) *types.EnrichedResourceDescription {
	a, _ := arn.Parse(userDL.Arn)

	return &types.EnrichedResourceDescription{
		Identifier: userDL.UserName,
		TypeName:   "AWS::IAM::User",
		Region:     "",
		AccountId:  a.AccountID,
		Arn:        a,
	}
}

func NewEnrichedResourceDescriptionFromGroupDL(groupDL GroupDetail) *types.EnrichedResourceDescription {
	a, _ := arn.Parse(groupDL.Arn)

	return &types.EnrichedResourceDescription{
		Identifier: groupDL.GroupName,
		TypeName:   "AWS::IAM::Group",
		Region:     "",
		AccountId:  a.AccountID,
		Arn:        a,
	}
}
