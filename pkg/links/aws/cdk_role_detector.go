package aws

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

// CDKRoleInfo represents a detected CDK role
type CDKRoleInfo struct {
	RoleName        string `json:"role_name"`
	RoleArn         string `json:"role_arn"`
	Qualifier       string `json:"qualifier"`
	Region          string `json:"region"`
	AccountID       string `json:"account_id"`
	CreationDate    string `json:"creation_date"`
	RoleType        string `json:"role_type"` // cfn-exec-role, file-publishing-role, etc.
	BucketName      string `json:"expected_bucket_name"`
	TrustPolicy     string `json:"trust_policy,omitempty"`
	AssumeRoleDoc   string `json:"assume_role_policy_document,omitempty"`
}

type AwsCdkRoleDetector struct {
	*base.AwsReconBaseLink
}

func NewAwsCdkRoleDetector(configs ...cfg.Config) chain.Link {
	link := &AwsCdkRoleDetector{}
	link.AwsReconBaseLink = base.NewAwsReconBaseLink(link, configs...)
	link.Base.SetName("AWS CDK Role Detector")
	return link
}

func (l *AwsCdkRoleDetector) Params() []cfg.Param {
	return append(options.AwsCommonReconOptions(), 
		options.AwsCdkQualifiers(),
	)
}

func (l *AwsCdkRoleDetector) Process(input any) error {
	var qualifiers []string
	var accountID string
	var regions []string

	// Check if input contains discovered qualifier info from previous link
	if qualInfo, ok := input.(CDKQualifierInfo); ok {
		qualifiers = qualInfo.Qualifiers
		accountID = qualInfo.AccountID
		regions = qualInfo.Regions
		l.Logger.Info("using discovered CDK qualifiers", "qualifiers", qualifiers, "account_id", accountID, "regions", regions)
	} else {
		// Fallback to manual configuration (backward compatibility)
		var err error
		qualifiers, err = cfg.As[[]string](l.Arg("cdk-qualifiers"))
		if err != nil || len(qualifiers) == 0 {
			qualifiers = []string{"hnb659fds"} // Default CDK qualifier
		}

		// Get current account ID
		accountID, err = l.getCurrentAccountID()
		if err != nil {
			l.Logger.Debug("failed to get current account ID", "error", err)
			return fmt.Errorf("failed to get current account ID: %w", err)
		}

		// Get regions to check - use configured regions or default to us-east-1 for CDK
		regions = []string{"us-east-1"} // CDK roles are typically in us-east-1
		configuredRegions, err := cfg.As[[]string](l.Arg("regions"))
		if err == nil && len(configuredRegions) > 0 {
			// If regions are explicitly configured, use them instead of default
			regions = configuredRegions
		}

		l.Logger.Info("scanning for CDK roles (manual config)", "account_id", accountID, "qualifiers", qualifiers)
	}

	var allRoles []CDKRoleInfo

	for _, region := range regions {
		roleInfos, err := l.detectCDKRolesInRegion(accountID, region, qualifiers)
		if err != nil {
			l.Logger.Debug("failed to detect CDK roles in region", "region", region, "error", err)
			continue
		}
		allRoles = append(allRoles, roleInfos...)
	}

	if len(allRoles) == 0 {
		l.Logger.Info("no CDK bootstrap roles found")
		return l.Send(map[string]any{
			"status": "no_cdk_roles_found",
			"account_id": accountID,
			"checked_qualifiers": qualifiers,
			"checked_regions": regions,
		})
	}

	l.Logger.Info("found CDK roles", "count", len(allRoles))
	
	// Send each role as separate output for the next link
	for _, roleInfo := range allRoles {
		if err := l.Send(roleInfo); err != nil {
			l.Logger.Debug("failed to send CDK role info", "role", roleInfo.RoleName, "error", err)
		}
	}

	return nil
}

func (l *AwsCdkRoleDetector) getCurrentAccountID() (string, error) {
	awsConfig, err := l.GetConfigWithRuntimeArgs("us-east-1")
	if err != nil {
		return "", fmt.Errorf("failed to get AWS config: %w", err)
	}

	client := sts.NewFromConfig(awsConfig)
	result, err := client.GetCallerIdentity(l.Context(), &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("failed to get caller identity: %w", err)
	}

	if result.Account == nil {
		return "", fmt.Errorf("account ID not found in caller identity")
	}

	return *result.Account, nil
}

func (l *AwsCdkRoleDetector) detectCDKRolesInRegion(accountID, region string, qualifiers []string) ([]CDKRoleInfo, error) {
	awsConfig, err := l.GetConfigWithRuntimeArgs(region)
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS config for region %s: %w", region, err)
	}

	client := iam.NewFromConfig(awsConfig)
	
	var roles []CDKRoleInfo
	
	// CDK role patterns to look for - focus on file-publishing-role as most vulnerable
	cdkRoleTypes := map[string]string{
		"file-publishing-role": "File Publishing Role", 
		"cfn-exec-role":      "CloudFormation Execution Role",
		"image-publishing-role": "Image Publishing Role",
		"lookup-role":        "Lookup Role",
		"deploy-role":        "Deploy Role",
	}

	for _, qualifier := range qualifiers {
		for roleType := range cdkRoleTypes {
			roleName := fmt.Sprintf("cdk-%s-%s-%s-%s", qualifier, roleType, accountID, region)
			
			l.Logger.Debug("checking for CDK role", "role_name", roleName, "region", region)
			
			roleInfo, err := l.getCDKRoleInfo(client, roleName, qualifier, region, accountID, roleType)
			if err != nil {
				l.Logger.Debug("CDK role not found or error", "role_name", roleName, "error", err)
				continue
			}
			
			if roleInfo != nil {
				l.Logger.Debug("found CDK role", "role_name", roleName, "type", roleType)
				roles = append(roles, *roleInfo)
			}
		}
	}

	return roles, nil
}

func (l *AwsCdkRoleDetector) getCDKRoleInfo(client *iam.Client, roleName, qualifier, region, accountID, roleType string) (*CDKRoleInfo, error) {
	// Try to get the role
	getRoleResult, err := client.GetRole(l.Context(), &iam.GetRoleInput{
		RoleName: &roleName,
	})
	if err != nil {
		// Role doesn't exist or we don't have permission
		return nil, err
	}

	if getRoleResult.Role == nil {
		return nil, fmt.Errorf("role result is nil")
	}

	role := getRoleResult.Role
	
	// Extract creation date
	createdDate := ""
	if role.CreateDate != nil {
		createdDate = role.CreateDate.Format("2006-01-02T15:04:05Z")
	}

	// Extract trust policy if available
	trustPolicy := ""
	if role.AssumeRolePolicyDocument != nil {
		trustPolicy = *role.AssumeRolePolicyDocument
	}

	// Generate expected bucket name
	bucketName := fmt.Sprintf("cdk-%s-assets-%s-%s", qualifier, accountID, region)

	roleInfo := &CDKRoleInfo{
		RoleName:            roleName,
		RoleArn:             *role.Arn,
		Qualifier:           qualifier,
		Region:              region,
		AccountID:           accountID,
		CreationDate:        createdDate,
		RoleType:            roleType,
		BucketName:          bucketName,
		AssumeRoleDoc:       trustPolicy,
	}

	// Try to get inline policies for additional context
	listPoliciesResult, err := client.ListRolePolicies(l.Context(), &iam.ListRolePoliciesInput{
		RoleName: &roleName,
	})
	if err == nil && listPoliciesResult.PolicyNames != nil && len(listPoliciesResult.PolicyNames) > 0 {
		// Get the first inline policy for additional context
		policyName := listPoliciesResult.PolicyNames[0]
		getPolicyResult, err := client.GetRolePolicy(l.Context(), &iam.GetRolePolicyInput{
			RoleName:   &roleName,
			PolicyName: &policyName,
		})
		if err == nil && getPolicyResult.PolicyDocument != nil {
			roleInfo.TrustPolicy = *getPolicyResult.PolicyDocument
		}
	}

	return roleInfo, nil
}