package cdk

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func detectRolesInRegion(ctx context.Context, client *iam.Client, accountID, region string, qualifiers []string) []RoleInfo {
	slog.Debug("detecting CDK roles", "region", region)
	var roles []RoleInfo

	for _, qualifier := range qualifiers {
		for roleType := range cdkRoleTypes {
			roleName := fmt.Sprintf("cdk-%s-%s-%s-%s", qualifier, roleType, accountID, region)

			roleInfo, err := getRoleInfo(ctx, client, roleName, qualifier, region, accountID, roleType)
			if err != nil {
				continue
			}
			if roleInfo != nil {
				slog.Debug("matched CDK role", "role", roleName, "type", roleType, "qualifier", qualifier)
				roles = append(roles, *roleInfo)
			}
		}
	}

	return roles
}

func getRoleInfo(ctx context.Context, client *iam.Client, roleName, qualifier, region, accountID, roleType string) (*RoleInfo, error) {
	result, err := client.GetRole(ctx, &iam.GetRoleInput{
		RoleName: &roleName,
	})
	if err != nil {
		return nil, fmt.Errorf("get role %s: %w", roleName, err)
	}
	if result.Role == nil {
		return nil, fmt.Errorf("role result is nil")
	}

	role := result.Role

	createdDate := ""
	if role.CreateDate != nil {
		createdDate = role.CreateDate.Format("2006-01-02T15:04:05Z")
	}

	trustPolicy := ""
	if role.AssumeRolePolicyDocument != nil {
		trustPolicy = *role.AssumeRolePolicyDocument
	}

	bucketName := fmt.Sprintf("cdk-%s-assets-%s-%s", qualifier, accountID, region)

	info := &RoleInfo{
		RoleName:      roleName,
		RoleArn:       *role.Arn,
		Qualifier:     qualifier,
		Region:        region,
		AccountID:     accountID,
		CreationDate:  createdDate,
		RoleType:      roleType,
		BucketName:    bucketName,
		AssumeRoleDoc: trustPolicy,
	}

	listResult, err := client.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
		RoleName: &roleName,
	})
	if err == nil && len(listResult.PolicyNames) > 0 {
		policyName := listResult.PolicyNames[0]
		getPolicyResult, err := client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
			RoleName:   &roleName,
			PolicyName: &policyName,
		})
		if err == nil && getPolicyResult.PolicyDocument != nil {
			info.TrustPolicy = *getPolicyResult.PolicyDocument
		}
	}

	return info, nil
}
