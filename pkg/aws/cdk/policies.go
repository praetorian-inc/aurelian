package cdk

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

func analyzePolicies(ctx context.Context, client *iam.Client, role RoleInfo) *output.Risk {
	if !strings.Contains(role.RoleType, "file-publishing-role") {
		return nil
	}

	slog.Debug("analyzing policies for role", "role", role.RoleName)

	hasRestriction, err := analyzeRoleS3Policies(ctx, client, role.RoleName, role.AccountID)
	if err != nil || hasRestriction {
		slog.Debug("account restriction found", "role", role.RoleName)
		return nil
	}

	slog.Debug("no account restriction found", "role", role.RoleName)
	return generatePolicyRisk(role)
}

func analyzeRoleS3Policies(ctx context.Context, client *iam.Client, roleName, accountID string) (bool, error) {
	inlinePolicies, err := client.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
		RoleName: &roleName,
	})
	if err != nil {
		return false, fmt.Errorf("failed to list inline policies: %w", err)
	}

	for _, policyName := range inlinePolicies.PolicyNames {
		policyDoc, err := client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
			RoleName:   &roleName,
			PolicyName: &policyName,
		})
		if err != nil {
			continue
		}
		if policyDoc.PolicyDocument != nil {
			if checkPolicyForAccountRestriction(*policyDoc.PolicyDocument, accountID) {
				return true, nil
			}
		}
	}

	attachedPolicies, err := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: &roleName,
	})
	if err != nil {
		slog.Debug("failed to list attached policies", "role", roleName, "error", err)
		return false, nil
	}

	for _, policy := range attachedPolicies.AttachedPolicies {
		if policy.PolicyArn == nil {
			continue
		}
		policyDetail, err := client.GetPolicy(ctx, &iam.GetPolicyInput{
			PolicyArn: policy.PolicyArn,
		})
		if err != nil || policyDetail.Policy == nil || policyDetail.Policy.DefaultVersionId == nil {
			continue
		}
		policyVersion, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
			PolicyArn: policy.PolicyArn,
			VersionId: policyDetail.Policy.DefaultVersionId,
		})
		if err != nil {
			continue
		}
		if policyVersion.PolicyVersion != nil && policyVersion.PolicyVersion.Document != nil {
			if checkPolicyForAccountRestriction(*policyVersion.PolicyVersion.Document, accountID) {
				return true, nil
			}
		}
	}

	return false, nil
}

func checkPolicyForAccountRestriction(policyDoc, accountID string) bool {
	var policy map[string]any

	if err := json.Unmarshal([]byte(policyDoc), &policy); err != nil {
		decoded, decodeErr := url.QueryUnescape(policyDoc)
		if decodeErr != nil {
			return false
		}
		if err := json.Unmarshal([]byte(decoded), &policy); err != nil {
			return false
		}
	}

	statements, ok := policy["Statement"].([]any)
	if !ok {
		return false
	}

	for _, stmt := range statements {
		statement, ok := stmt.(map[string]any)
		if !ok {
			continue
		}
		if !statementAffectsS3(statement) {
			continue
		}
		// Check for aws:ResourceAccount condition — this is the ONLY reliable check.
		// We intentionally do NOT check if account ID appears in bucket ARNs because:
		// 1. S3 bucket names are globally unique across ALL AWS accounts
		// 2. An IAM permission to arn:aws:s3:::bucket-name works regardless of bucket owner
		// 3. The account ID in CDK bucket names is just a naming convention, not access control
		// 4. Only aws:ResourceAccount condition actually restricts to same-account buckets
		if hasResourceAccountCondition(statement, accountID) {
			return true
		}
	}

	return false
}

func statementAffectsS3(statement map[string]any) bool {
	actions, ok := statement["Action"]
	if !ok {
		return false
	}

	var actionList []string
	switch a := actions.(type) {
	case string:
		actionList = []string{a}
	case []any:
		for _, action := range a {
			if actionStr, ok := action.(string); ok {
				actionList = append(actionList, actionStr)
			}
		}
	default:
		return false
	}

	return slices.ContainsFunc(actionList, func(action string) bool {
		return strings.HasPrefix(strings.ToLower(action), "s3:")
	})
}

func hasResourceAccountCondition(statement map[string]any, accountID string) bool {
	condition, ok := statement["Condition"].(map[string]any)
	if !ok {
		return false
	}

	for condType, condValues := range condition {
		if condType != "StringEquals" && condType != "StringLike" {
			continue
		}
		condMap, ok := condValues.(map[string]any)
		if !ok {
			continue
		}
		if resourceAccount, exists := condMap["aws:ResourceAccount"]; exists {
			switch ra := resourceAccount.(type) {
			case string:
				if ra == accountID {
					return true
				}
			case []any:
				for _, val := range ra {
					if valStr, ok := val.(string); ok && valStr == accountID {
						return true
					}
				}
			}
		}
	}
	return false
}

func generatePolicyRisk(role RoleInfo) *output.Risk {
	accountArn := fmt.Sprintf("arn:aws:iam::%s:root", role.AccountID)
	return &output.Risk{
		Target: &output.AWSResource{
			ResourceType: "AWS::IAM::Root",
			ResourceID:   accountArn,
			AccountRef:   role.AccountID,
			Region:       role.Region,
			Properties: map[string]any{
				"RoleName":   role.RoleName,
				"BucketName": role.BucketName,
				"Qualifier":  role.Qualifier,
			},
		},
		Name:           "cdk-policy-unrestricted",
		DNS:            role.AccountID,
		Status:         "TM",
		Source:         "aurelian-cdk-scanner",
		Description:    fmt.Sprintf("AWS CDK FilePublishingRole '%s' lacks proper account restrictions in S3 permissions. This role can potentially access S3 buckets in other accounts, making it vulnerable to bucket takeover attacks.", role.RoleName),
		Impact:         "The role may inadvertently access attacker-controlled S3 buckets with the same predictable name, allowing CloudFormation template injection.",
		Recommendation: fmt.Sprintf("Upgrade to CDK v2.149.0+ and re-run 'cdk bootstrap' in region %s, or manually add 'aws:ResourceAccount' condition to the role's S3 permissions.", role.Region),
		References:     "https://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover/",
		Comment:        fmt.Sprintf("Role: %s, Bucket: %s, Qualifier: %s, Region: %s", role.RoleName, role.BucketName, role.Qualifier, role.Region),
	}
}
