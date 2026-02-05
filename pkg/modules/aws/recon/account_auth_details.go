package recon

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	plugin.Register(&AWSAccountAuthDetailsModule{})
}

// AWSAccountAuthDetailsModule retrieves IAM authorization details
type AWSAccountAuthDetailsModule struct{}

func (m *AWSAccountAuthDetailsModule) ID() string {
	return "account-auth-details"
}

func (m *AWSAccountAuthDetailsModule) Name() string {
	return "AWS Get Account Authorization Details"
}

func (m *AWSAccountAuthDetailsModule) Description() string {
	return "Get authorization details in an AWS account."
}

func (m *AWSAccountAuthDetailsModule) Platform() plugin.Platform {
	return plugin.PlatformAWS
}

func (m *AWSAccountAuthDetailsModule) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *AWSAccountAuthDetailsModule) OpsecLevel() string {
	return "moderate"
}

func (m *AWSAccountAuthDetailsModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *AWSAccountAuthDetailsModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html",
		"https://pkg.go.dev/github.com/aws/aws-sdk-go-v2/service/iam#Client.GetAccountAuthorizationDetails",
	}
}

func (m *AWSAccountAuthDetailsModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "profile",
			Description: "AWS profile name",
			Type:        "string",
		},
		{
			Name:        "profile-dir",
			Description: "AWS profile directory",
			Type:        "string",
		},
	}
}

func (m *AWSAccountAuthDetailsModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Get parameters
	profile, _ := cfg.Args["profile"].(string)
	profileDir, _ := cfg.Args["profile-dir"].(string)

	// Build opts slice for GetAWSCfg
	var opts []*types.Option
	if profileDir != "" {
		opts = append(opts, &types.Option{
			Name:  "profile-dir",
			Value: profileDir,
		})
	}

	// IAM is a global service, use us-east-1
	awsCfg, err := helpers.GetAWSCfg("us-east-1", profile, opts, "moderate")
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS config: %w", err)
	}

	// Get account authorization details
	details, err := m.getAccountAuthDetails(cfg.Context, awsCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to get account authorization details: %w", err)
	}

	return []plugin.Result{
		{
			Data: details,
			Metadata: map[string]any{
				"module":      "account-auth-details",
				"platform":    "aws",
				"opsec_level": "moderate",
			},
		},
	}, nil
}

func (m *AWSAccountAuthDetailsModule) getAccountAuthDetails(ctx context.Context, awsCfg aws.Config) (map[string]any, error) {
	client := iam.NewFromConfig(awsCfg)

	result := map[string]any{
		"users":        []any{},
		"groups":       []any{},
		"roles":        []any{},
		"policies":     []any{},
	}

	var marker *string
	for {
		input := &iam.GetAccountAuthorizationDetailsInput{
			Filter: nil, // Get all entity types
		}
		if marker != nil {
			input.Marker = marker
		}

		output, err := client.GetAccountAuthorizationDetails(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to call GetAccountAuthorizationDetails: %w", err)
		}

		// Process users
		for _, user := range output.UserDetailList {
			userInfo := map[string]any{
				"user_name": aws.ToString(user.UserName),
				"user_id":   aws.ToString(user.UserId),
				"arn":       aws.ToString(user.Arn),
				"path":      aws.ToString(user.Path),
			}
			if user.CreateDate != nil {
				userInfo["create_date"] = user.CreateDate.String()
			}

			// Add attached policies
			var attachedPolicies []string
			for _, policy := range user.AttachedManagedPolicies {
				attachedPolicies = append(attachedPolicies, aws.ToString(policy.PolicyArn))
			}
			userInfo["attached_policies"] = attachedPolicies

			// Add inline policies
			var inlinePolicies []string
			for _, policy := range user.UserPolicyList {
				inlinePolicies = append(inlinePolicies, aws.ToString(policy.PolicyName))
			}
			userInfo["inline_policies"] = inlinePolicies

			// Add groups
			var groups []string
			for _, group := range user.GroupList {
				groups = append(groups, group)
			}
			userInfo["groups"] = groups

			result["users"] = append(result["users"].([]any), userInfo)
		}

		// Process groups
		for _, group := range output.GroupDetailList {
			groupInfo := map[string]any{
				"group_name": aws.ToString(group.GroupName),
				"group_id":   aws.ToString(group.GroupId),
				"arn":        aws.ToString(group.Arn),
				"path":       aws.ToString(group.Path),
			}
			if group.CreateDate != nil {
				groupInfo["create_date"] = group.CreateDate.String()
			}

			// Add attached policies
			var attachedPolicies []string
			for _, policy := range group.AttachedManagedPolicies {
				attachedPolicies = append(attachedPolicies, aws.ToString(policy.PolicyArn))
			}
			groupInfo["attached_policies"] = attachedPolicies

			// Add inline policies
			var inlinePolicies []string
			for _, policy := range group.GroupPolicyList {
				inlinePolicies = append(inlinePolicies, aws.ToString(policy.PolicyName))
			}
			groupInfo["inline_policies"] = inlinePolicies

			result["groups"] = append(result["groups"].([]any), groupInfo)
		}

		// Process roles
		for _, role := range output.RoleDetailList {
			roleInfo := map[string]any{
				"role_name": aws.ToString(role.RoleName),
				"role_id":   aws.ToString(role.RoleId),
				"arn":       aws.ToString(role.Arn),
				"path":      aws.ToString(role.Path),
			}
			if role.CreateDate != nil {
				roleInfo["create_date"] = role.CreateDate.String()
			}

			// Add trust policy
			if role.AssumeRolePolicyDocument != nil {
				roleInfo["assume_role_policy"] = aws.ToString(role.AssumeRolePolicyDocument)
			}

			// Add attached policies
			var attachedPolicies []string
			for _, policy := range role.AttachedManagedPolicies {
				attachedPolicies = append(attachedPolicies, aws.ToString(policy.PolicyArn))
			}
			roleInfo["attached_policies"] = attachedPolicies

			// Add inline policies
			var inlinePolicies []string
			for _, policy := range role.RolePolicyList {
				inlinePolicies = append(inlinePolicies, aws.ToString(policy.PolicyName))
			}
			roleInfo["inline_policies"] = inlinePolicies

			result["roles"] = append(result["roles"].([]any), roleInfo)
		}

		// Process policies
		for _, policy := range output.Policies {
			policyInfo := map[string]any{
				"policy_name": aws.ToString(policy.PolicyName),
				"policy_id":   aws.ToString(policy.PolicyId),
				"arn":         aws.ToString(policy.Arn),
				"path":        aws.ToString(policy.Path),
				"is_attachable": policy.IsAttachable,
			}
			if policy.CreateDate != nil {
				policyInfo["create_date"] = policy.CreateDate.String()
			}
			if policy.UpdateDate != nil {
				policyInfo["update_date"] = policy.UpdateDate.String()
			}

			// Add policy versions
			var versions []map[string]any
			for _, version := range policy.PolicyVersionList {
				versionInfo := map[string]any{
					"version_id":         aws.ToString(version.VersionId),
					"is_default_version": version.IsDefaultVersion,
				}
				if version.CreateDate != nil {
					versionInfo["create_date"] = version.CreateDate.String()
				}
				if version.Document != nil {
					versionInfo["document"] = aws.ToString(version.Document)
				}
				versions = append(versions, versionInfo)
			}
			policyInfo["versions"] = versions

			result["policies"] = append(result["policies"].([]any), policyInfo)
		}

		// Check for more data
		marker = output.Marker
		if marker == nil || !output.IsTruncated {
			break
		}
	}

	// Add summary counts
	result["summary"] = map[string]any{
		"user_count":   len(result["users"].([]any)),
		"group_count":  len(result["groups"].([]any)),
		"role_count":   len(result["roles"].([]any)),
		"policy_count": len(result["policies"].([]any)),
	}

	return result, nil
}
