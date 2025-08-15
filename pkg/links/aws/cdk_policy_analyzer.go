package aws

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

type AwsCdkPolicyAnalyzer struct {
	*base.AwsReconBaseLink
}

func NewAwsCdkPolicyAnalyzer(configs ...cfg.Config) chain.Link {
	link := &AwsCdkPolicyAnalyzer{}
	link.AwsReconBaseLink = base.NewAwsReconBaseLink(link, configs...)
	link.Base.SetName("AWS CDK Policy Analyzer")
	return link
}

func (l *AwsCdkPolicyAnalyzer) Params() []cfg.Param {
	return l.AwsReconBaseLink.Params()
}

func (l *AwsCdkPolicyAnalyzer) Process(input any) error {
	// Try to extract CDKRoleInfo from input
	cdkRole, ok := input.(CDKRoleInfo)
	if !ok {
		// Pass through non-CDKRoleInfo objects (like Risk objects from other links)
		l.Logger.Debug("input is not CDKRoleInfo, passing through")
		return l.Send(input)
	}

	// Only analyze FilePublishingRole as it's the one vulnerable to cross-account bucket access
	// This matches the focus of the reference vulnerability scanner
	if !strings.Contains(cdkRole.RoleType, "file-publishing-role") {
		l.Logger.Debug("skipping non-file-publishing role", "role_type", cdkRole.RoleType)
		return l.Send(cdkRole) // Pass through for other processing
	}

	l.Logger.Info("analyzing CDK file publishing role policies", "role", cdkRole.RoleName)

	awsConfig, err := l.GetConfigWithRuntimeArgs(cdkRole.Region)
	if err != nil {
		l.Logger.Debug("failed to get AWS config", "region", cdkRole.Region, "error", err)
		return nil // Don't fail the entire chain
	}

	iamClient := iam.NewFromConfig(awsConfig)

	// Analyze role's inline and attached policies for S3 permissions
	hasAccountRestriction, err := l.analyzeRoleS3Policies(iamClient, cdkRole.RoleName, cdkRole.AccountID)
	if err != nil {
		l.Logger.Debug("error analyzing role policies", "role", cdkRole.RoleName, "error", err)
		return l.Send(cdkRole) // Pass through even if analysis fails
	}

	// Generate risk if role lacks proper account restrictions
	if !hasAccountRestriction {
		risk := l.generatePolicyRisk(cdkRole)
		if risk != nil {
			l.Logger.Info("found CDK policy vulnerability", "role", cdkRole.RoleName, "risk", risk.Name)
			return l.Send(*risk)
		}
	}

	// No policy issues found, pass through the role info
	return l.Send(cdkRole)
}

func (l *AwsCdkPolicyAnalyzer) analyzeRoleS3Policies(iamClient *iam.Client, roleName, accountID string) (bool, error) {
	hasAccountRestriction := false

	// Check inline policies
	inlinePolicies, err := iamClient.ListRolePolicies(l.Context(), &iam.ListRolePoliciesInput{
		RoleName: &roleName,
	})
	if err != nil {
		return false, fmt.Errorf("failed to list inline policies: %w", err)
	}

	for _, policyName := range inlinePolicies.PolicyNames {
		policyDoc, err := iamClient.GetRolePolicy(l.Context(), &iam.GetRolePolicyInput{
			RoleName:   &roleName,
			PolicyName: &policyName,
		})
		if err != nil {
			l.Logger.Debug("failed to get inline policy", "policy", policyName, "error", err)
			continue
		}

		if policyDoc.PolicyDocument != nil {
			if l.checkPolicyForAccountRestriction(*policyDoc.PolicyDocument, accountID) {
				hasAccountRestriction = true
				break
			}
		}
	}

	// If not found in inline policies, check attached managed policies
	if !hasAccountRestriction {
		attachedPolicies, err := iamClient.ListAttachedRolePolicies(l.Context(), &iam.ListAttachedRolePoliciesInput{
			RoleName: &roleName,
		})
		if err == nil {
			for _, policy := range attachedPolicies.AttachedPolicies {
				if policy.PolicyArn == nil {
					continue
				}

				// Get the default version of the managed policy
				policyVersion, err := iamClient.GetPolicyVersion(l.Context(), &iam.GetPolicyVersionInput{
					PolicyArn: policy.PolicyArn,
					VersionId: policy.PolicyArn, // Use default version
				})
				if err != nil {
					l.Logger.Debug("failed to get managed policy version", "arn", *policy.PolicyArn, "error", err)
					continue
				}

				if policyVersion.PolicyVersion != nil && policyVersion.PolicyVersion.Document != nil {
					if l.checkPolicyForAccountRestriction(*policyVersion.PolicyVersion.Document, accountID) {
						hasAccountRestriction = true
						break
					}
				}
			}
		}
	}

	return hasAccountRestriction, nil
}

func (l *AwsCdkPolicyAnalyzer) checkPolicyForAccountRestriction(policyDoc, accountID string) bool {
	// Parse the policy document JSON
	var policy map[string]any
	if err := json.Unmarshal([]byte(policyDoc), &policy); err != nil {
		l.Logger.Debug("failed to parse policy document", "error", err)
		return false
	}

	// Check if policy has Statement array
	statements, ok := policy["Statement"].([]any)
	if !ok {
		return false
	}

	// Look for S3 permissions with account restrictions
	for _, stmt := range statements {
		statement, ok := stmt.(map[string]any)
		if !ok {
			continue
		}

		// Check if this statement affects S3
		if !l.statementAffectsS3(statement) {
			continue
		}

		// Check for aws:ResourceAccount condition
		if l.hasResourceAccountCondition(statement, accountID) {
			l.Logger.Debug("found aws:ResourceAccount condition in policy")
			return true
		}

		// Check for explicit account restriction in Resource ARNs  
		if l.hasAccountRestrictedResources(statement, accountID) {
			l.Logger.Debug("found account-restricted resources in policy")
			return true
		}
	}

	return false
}

func (l *AwsCdkPolicyAnalyzer) statementAffectsS3(statement map[string]any) bool {
	actions, ok := statement["Action"]
	if !ok {
		return false
	}

	// Convert action to string slice for easier checking
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

	// Check if any action is S3-related
	for _, action := range actionList {
		if strings.HasPrefix(strings.ToLower(action), "s3:") {
			return true
		}
	}

	return false
}

func (l *AwsCdkPolicyAnalyzer) hasResourceAccountCondition(statement map[string]any, accountID string) bool {
	condition, ok := statement["Condition"].(map[string]any)
	if !ok {
		return false
	}

	// Check for StringEquals or StringLike conditions
	for condType, condValues := range condition {
		if condType != "StringEquals" && condType != "StringLike" {
			continue
		}

		condMap, ok := condValues.(map[string]any)
		if !ok {
			continue
		}

		// Check for aws:ResourceAccount condition
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

func (l *AwsCdkPolicyAnalyzer) hasAccountRestrictedResources(statement map[string]any, accountID string) bool {
	resources, ok := statement["Resource"]
	if !ok {
		return false
	}

	// Convert resource to string slice for easier checking
	var resourceList []string
	switch r := resources.(type) {
	case string:
		resourceList = []string{r}
	case []any:
		for _, resource := range r {
			if resourceStr, ok := resource.(string); ok {
				resourceList = append(resourceList, resourceStr)
			}
		}
	default:
		return false
	}

	// Check if all S3 resources are restricted to our account
	for _, resource := range resourceList {
		if strings.HasPrefix(resource, "arn:aws:s3:::") {
			// If resource contains our account ID or is very specific, it's restricted
			if strings.Contains(resource, accountID) {
				return true
			}
		}
	}

	return false
}

func (l *AwsCdkPolicyAnalyzer) generatePolicyRisk(cdkRole CDKRoleInfo) *model.Risk {
	// Create an AWS account target using AWSResource
	accountArn := fmt.Sprintf("arn:aws:iam::%s:root", cdkRole.AccountID)
	awsAccount, err := model.NewAWSResource(accountArn, cdkRole.AccountID, model.CloudResourceType("AWS::IAM::Root"), map[string]any{
		"RoleName": cdkRole.RoleName,
		"BucketName": cdkRole.BucketName,
		"Qualifier": cdkRole.Qualifier,
		"Region": cdkRole.Region,
	})
	if err != nil {
		l.Logger.Debug("failed to create AWS resource target", "error", err)
		return nil
	}

	risk := model.NewRiskWithDNS(
		&awsAccount,
		"cdk-policy-unrestricted",
		cdkRole.AccountID,
		model.TriageMedium,
	)
	risk.Source = "nebula-cdk-scanner"

	riskDef := model.RiskDefinition{
		Description: fmt.Sprintf("AWS CDK FilePublishingRole '%s' lacks proper account restrictions in S3 permissions. This role can potentially access S3 buckets in other accounts, making it vulnerable to bucket takeover attacks.", cdkRole.RoleName),
		Impact:      "The role may inadvertently access attacker-controlled S3 buckets with the same predictable name, allowing CloudFormation template injection.",
		Recommendation: fmt.Sprintf("Upgrade to CDK v2.149.0+ and re-run 'cdk bootstrap' in region %s, or manually add 'aws:ResourceAccount' condition to the role's S3 permissions.", cdkRole.Region),
		References:  "https://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover/",
	}

	risk.Comment = fmt.Sprintf("Role: %s, Bucket: %s, Qualifier: %s, Region: %s",
		cdkRole.RoleName, cdkRole.BucketName, cdkRole.Qualifier, cdkRole.Region)

	risk.Definition(riskDef)

	return &risk
}