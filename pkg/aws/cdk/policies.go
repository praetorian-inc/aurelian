package cdk

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iameval "github.com/praetorian-inc/aurelian/pkg/aws/iam"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
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

// parsePolicyDoc unmarshals a policy document string (raw or URL-encoded) into
// a types.Policy. Unlike types.NewPolicyFromJSON it does not require Version.
func parsePolicyDoc(policyDoc string) (*types.Policy, error) {
	var policy types.Policy
	if err := json.Unmarshal([]byte(policyDoc), &policy); err != nil {
		decoded, decodeErr := url.QueryUnescape(policyDoc)
		if decodeErr != nil {
			return nil, decodeErr
		}
		if err := json.Unmarshal([]byte(decoded), &policy); err != nil {
			return nil, err
		}
	}
	return &policy, nil
}

func checkPolicyForAccountRestriction(policyDoc, accountID string) bool {
	policy, err := parsePolicyDoc(policyDoc)
	if err != nil {
		return false
	}

	if policy.Statement == nil {
		return false
	}

	for _, stmt := range *policy.Statement {
		if !statementAffectsS3(&stmt) {
			continue
		}
		// Check for aws:ResourceAccount condition — this is the ONLY reliable check.
		// We intentionally do NOT check if account ID appears in bucket ARNs because:
		// 1. S3 bucket names are globally unique across ALL AWS accounts
		// 2. An IAM permission to arn:aws:s3:::bucket-name works regardless of bucket owner
		// 3. The account ID in CDK bucket names is just a naming convention, not access control
		// 4. Only aws:ResourceAccount condition actually restricts to same-account buckets
		if hasResourceAccountCondition(&stmt, accountID) {
			return true
		}
	}

	return false
}

func statementAffectsS3(stmt *types.PolicyStatement) bool {
	if stmt.Action == nil {
		return false
	}
	for _, action := range *stmt.Action {
		if strings.HasPrefix(strings.ToLower(action), "s3:") {
			return true
		}
	}
	return false
}

func hasResourceAccountCondition(stmt *types.PolicyStatement, accountID string) bool {
	if stmt.Condition == nil {
		return false
	}
	reqCtx := &iameval.RequestContext{
		ResourceAccount: accountID,
	}
	result := iameval.EvaluateConditions(stmt.Condition, reqCtx)
	if !result.Allowed() {
		return false
	}
	// Verify the condition actually references aws:ResourceAccount
	for key := range result.KeyResults {
		if strings.EqualFold(key, "aws:ResourceAccount") {
			return result.KeyResults[key].Result == iameval.ConditionMatched
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
