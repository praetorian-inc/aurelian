package aws

import (
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	iam "github.com/praetorian-inc/aurelian/pkg/iam/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// TransformUserDLToCloudResource converts a UserDL to a CloudResource with IAM User type
func TransformUserDLToCloudResource(user *types.UserDL) (*output.CloudResource, error) {
	if user == nil {
		return nil, fmt.Errorf("user cannot be nil")
	}

	// Extract account ID from ARN
	accountID := ""
	if user.Arn != "" {
		if parsedArn, err := arn.Parse(user.Arn); err == nil {
			accountID = parsedArn.AccountID
		}
	}

	properties := map[string]any{
		"userName": user.UserName,
		"path":     user.Path,
		"userId":   user.UserId,
	}

	// Add creation date if available
	if user.CreateDate != "" {
		properties["createDate"] = user.CreateDate
	}

	cloudResource := output.CloudResource{
		Platform:     "aws",
		ResourceType: "AWS::IAM::User",
		ResourceID:   user.Arn,
		AccountRef:   accountID,
		Properties:   properties,
	}

	return &cloudResource, nil
}

// TransformRoleDLToCloudResource converts a RoleDL to a CloudResource with IAM Role type
func TransformRoleDLToCloudResource(role *types.RoleDL) (*output.CloudResource, error) {
	if role == nil {
		return nil, fmt.Errorf("role cannot be nil")
	}

	// Extract account ID from ARN
	accountID := ""
	if role.Arn != "" {
		if parsedArn, err := arn.Parse(role.Arn); err == nil {
			accountID = parsedArn.AccountID
		}
	}

	properties := map[string]any{
		"roleName": role.RoleName,
		"path":     role.Path,
		"roleId":   role.RoleId,
	}

	// Add creation date if available
	if role.CreateDate != "" {
		properties["createDate"] = role.CreateDate
	}

	// Add assume role policy document if available
	// Note: AssumeRolePolicyDocument is a types.Policy, convert to string representation
	if role.AssumeRolePolicyDocument.Statement != nil {
		properties["assumeRolePolicyDocument"] = "present" // Could serialize if needed
	}

	cloudResource := output.CloudResource{
		Platform:     "aws",
		ResourceType: "AWS::IAM::Role",
		ResourceID:   role.Arn,
		AccountRef:   accountID,
		Properties:   properties,
	}

	return &cloudResource, nil
}

// TransformGroupDLToCloudResource converts a GroupDL to a CloudResource with IAM Group type
func TransformGroupDLToCloudResource(group *types.GroupDL) (*output.CloudResource, error) {
	if group == nil {
		return nil, fmt.Errorf("group cannot be nil")
	}

	// Extract account ID from ARN
	accountID := ""
	if group.Arn != "" {
		if parsedArn, err := arn.Parse(group.Arn); err == nil {
			accountID = parsedArn.AccountID
		}
	}

	properties := map[string]any{
		"groupName": group.GroupName,
		"path":      group.Path,
		"groupId":   group.GroupId,
	}

	// Add creation date if available
	if group.CreateDate != "" {
		properties["createDate"] = group.CreateDate
	}

	cloudResource := output.CloudResource{
		Platform:     "aws",
		ResourceType: "AWS::IAM::Group",
		ResourceID:   group.Arn,
		AccountRef:   accountID,
		Properties:   properties,
	}

	return &cloudResource, nil
}

// TransformERDToCloudResource converts an EnrichedResourceDescription to a CloudResource
func TransformERDToCloudResource(erd *types.EnrichedResourceDescription) (*output.CloudResource, error) {
	if erd == nil {
		return nil, fmt.Errorf("enriched resource description cannot be nil")
	}

	// Use TypeName as the resource type (already in CloudFormation format)
	cloudResourceType := erd.TypeName

	// Build properties from the enriched resource
	properties := make(map[string]any)
	if erd.Properties != nil {
		// Properties is stored as interface{}, try to convert to map
		if propsMap, ok := erd.Properties.(map[string]any); ok {
			for k, v := range propsMap {
				properties[k] = v
			}
		} else if propsStr, ok := erd.Properties.(string); ok {
			// Sometimes properties are stored as JSON strings
			properties["_raw_properties"] = propsStr
		} else {
			properties["_raw_properties"] = erd.Properties
		}
	}

	cloudResource := output.CloudResource{
		Platform:     "aws",
		ResourceType: cloudResourceType,
		ResourceID:   erd.Arn.String(),
		AccountRef:   erd.AccountId,
		Properties:   properties,
	}

	return &cloudResource, nil
}

// CreateResourceRefForServicePrincipal creates a ResourceRef for AWS service principals
func CreateResourceRefForServicePrincipal(principalString string) output.ResourceRef {
	return output.ResourceRef{
		Platform: "aws",
		Type:     "service-principal",
		ID:       principalString,
		Account:  "aws", // Service principals are AWS-owned
	}
}

// CreateResourceRefForPrincipal creates a ResourceRef for generic principals
func CreateResourceRefForPrincipal(principalString string) output.ResourceRef {
	// Extract account ID if it's an ARN
	accountID := ""
	if strings.HasPrefix(principalString, "arn:") {
		if parsedArn, err := arn.Parse(principalString); err == nil {
			accountID = parsedArn.AccountID
		}
	}

	return output.ResourceRef{
		Platform: "aws",
		Type:     "principal",
		ID:       principalString,
		Account:  accountID,
	}
}

// TransformUserDLToResourceRef converts a UserDL to a ResourceRef
func TransformUserDLToResourceRef(user *types.UserDL) (output.ResourceRef, error) {
	if user == nil {
		return output.ResourceRef{}, fmt.Errorf("user cannot be nil")
	}

	accountID := ""
	if user.Arn != "" {
		if parsedArn, err := arn.Parse(user.Arn); err == nil {
			accountID = parsedArn.AccountID
		}
	}

	return output.ResourceRef{
		Platform: "aws",
		Type:     "iam-user",
		ID:       user.Arn,
		Account:  accountID,
	}, nil
}

// TransformRoleDLToResourceRef converts a RoleDL to a ResourceRef
func TransformRoleDLToResourceRef(role *types.RoleDL) (output.ResourceRef, error) {
	if role == nil {
		return output.ResourceRef{}, fmt.Errorf("role cannot be nil")
	}

	accountID := ""
	if role.Arn != "" {
		if parsedArn, err := arn.Parse(role.Arn); err == nil {
			accountID = parsedArn.AccountID
		}
	}

	return output.ResourceRef{
		Platform: "aws",
		Type:     "iam-role",
		ID:       role.Arn,
		Account:  accountID,
	}, nil
}

// TransformGroupDLToResourceRef converts a GroupDL to a ResourceRef
func TransformGroupDLToResourceRef(group *types.GroupDL) (output.ResourceRef, error) {
	if group == nil {
		return output.ResourceRef{}, fmt.Errorf("group cannot be nil")
	}

	accountID := ""
	if group.Arn != "" {
		if parsedArn, err := arn.Parse(group.Arn); err == nil {
			accountID = parsedArn.AccountID
		}
	}

	return output.ResourceRef{
		Platform: "aws",
		Type:     "iam-group",
		ID:       group.Arn,
		Account:  accountID,
	}, nil
}

// TransformERDToResourceRef converts an EnrichedResourceDescription to a ResourceRef
func TransformERDToResourceRef(erd *types.EnrichedResourceDescription) (output.ResourceRef, error) {
	if erd == nil {
		return output.ResourceRef{}, fmt.Errorf("enriched resource description cannot be nil")
	}

	return output.ResourceRef{
		Platform: "aws",
		Type:     strings.ToLower(strings.ReplaceAll(erd.TypeName, "::", "-")), // e.g., "aws-s3-bucket"
		ID:       erd.Arn.String(),
		Account:  erd.AccountId,
	}, nil
}

// isSSMAction checks if the action is an SSM action that may have document restrictions
func isSSMAction(action string) bool {
	return strings.HasPrefix(action, "ssm:")
}

// TransformResultToPermission converts an iam.FullResult to an IAMPermission or SSMPermission
// Returns pure domain data - NO Neo4j key knowledge
func TransformResultToPermission(result iam.FullResult) (interface{}, error) {
	// Handle Principal (Source)
	var source output.ResourceRef
	var err error

	switch p := result.Principal.(type) {
	case *types.UserDL:
		source, err = TransformUserDLToResourceRef(p)
		if err != nil {
			return nil, fmt.Errorf("failed to transform user: %w", err)
		}
	case *types.RoleDL:
		source, err = TransformRoleDLToResourceRef(p)
		if err != nil {
			return nil, fmt.Errorf("failed to transform role: %w", err)
		}
	case *types.GroupDL:
		source, err = TransformGroupDLToResourceRef(p)
		if err != nil {
			return nil, fmt.Errorf("failed to transform group: %w", err)
		}
	case string:
		// Handle service principals
		if strings.Contains(p, "amazonaws.com") || strings.Contains(p, "aws:service") {
			source = CreateResourceRefForServicePrincipal(p)
		} else {
			source = CreateResourceRefForPrincipal(p)
		}
	default:
		return nil, fmt.Errorf("unknown principal type: %T", p)
	}

	// Handle Resource (Target)
	if result.Resource == nil {
		return nil, fmt.Errorf("nil resource")
	}

	target, err := TransformERDToResourceRef(result.Resource)
	if err != nil {
		return nil, fmt.Errorf("failed to transform resource: %w", err)
	}

	// Create timestamp in ISO 8601 format
	timestamp := time.Now().UTC().Format(time.RFC3339)

	// Check if this is an SSM action with document restrictions
	if isSSMAction(result.Action) && result.Result != nil && len(result.Result.SSMDocumentRestrictions) > 0 {
		// Check if shell execution is allowed (wildcard or RunShellScript/RunPowerShellScript)
		allowsShellExecution := false
		for _, doc := range result.Result.SSMDocumentRestrictions {
			if doc == "*" ||
				strings.Contains(doc, "RunShellScript") ||
				strings.Contains(doc, "RunPowerShellScript") {
				allowsShellExecution = true
				break
			}
		}

		// Create SSM-specific permission with document restrictions
		return &output.SSMPermission{
			IAMPermission: output.IAMPermission{
				Source:     source,
				Target:     target,
				Permission: result.Action,
				Effect:     "Allow", // Apollo evaluates actual permissions, so these are allowed
				Capability: "apollo-iam-analysis",
				Timestamp:  timestamp,
			},
			SSMDocumentRestrictions: result.Result.SSMDocumentRestrictions,
			AllowsShellExecution:    allowsShellExecution,
		}, nil
	}

	// Create standard IAM permission
	return &output.IAMPermission{
		Source:     source,
		Target:     target,
		Permission: result.Action,
		Effect:     "Allow", // Apollo evaluates actual permissions, so these are allowed
		Capability: "apollo-iam-analysis",
		Timestamp:  timestamp,
	}, nil
}

// CreateRepositoryFromGitHubSubject creates a Repository from GitHub Actions subject claims
func CreateRepositoryFromGitHubSubject(org, repo string) (*output.Repository, error) {
	if org == "" || repo == "" {
		return nil, fmt.Errorf("org and repo cannot be empty")
	}

	return &output.Repository{
		Platform: "github",
		Org:      org,
		Name:     repo,
		URL:      fmt.Sprintf("https://github.com/%s/%s", org, repo),
	}, nil
}

// CreateGitHubActionsPermission creates a GitHub Actions OIDC federation permission
// Returns pure domain data - NO Neo4j key knowledge
func CreateGitHubActionsPermission(
	repository *output.Repository,
	roleRef output.ResourceRef,
	subjectPatterns []string,
	conditions *types.Condition,
) (*output.GitHubActionsPermission, error) {
	if repository == nil {
		return nil, fmt.Errorf("repository cannot be nil")
	}

	if len(subjectPatterns) == 0 {
		return nil, fmt.Errorf("subject patterns cannot be empty")
	}

	// Create ResourceRef for the repository
	repoRef := output.ResourceRef{
		Platform: "github",
		Type:     "repository",
		ID:       repository.URL,
		Account:  repository.Org,
	}

	// Create timestamp in ISO 8601 format
	timestamp := time.Now().UTC().Format(time.RFC3339)

	return &output.GitHubActionsPermission{
		IAMPermission: output.IAMPermission{
			Source:     repoRef,
			Target:     roleRef,
			Permission: "sts:AssumeRoleWithWebIdentity",
			Effect:     "Allow",
			Capability: "apollo-github-actions-federation",
			Timestamp:  timestamp,
		},
		SubjectPatterns: subjectPatterns,
		RepositoryOrg:   repository.Org,
		RepositoryName:  repository.Name,
	}, nil
}

// ExtractGitHubActionsPermissions extracts all GitHub Actions Repository→Role permissions from GAAD data
func ExtractGitHubActionsPermissions(gaad *types.Gaad) ([]*output.GitHubActionsPermission, error) {
	permissions := make([]*output.GitHubActionsPermission, 0)

	if gaad == nil {
		return permissions, nil
	}

	// Process all roles for GitHub Actions assume role policies
	for _, role := range gaad.RoleDetailList {
		rolePerms, err := extractGitHubActionsPermissionsFromRole(&role)
		if err != nil {
			// Log error but continue processing
			continue
		}
		permissions = append(permissions, rolePerms...)
	}

	return permissions, nil
}

// extractGitHubActionsPermissionsFromRole extracts GitHub Actions permissions from a single role
func extractGitHubActionsPermissionsFromRole(role *types.RoleDL) ([]*output.GitHubActionsPermission, error) {
	permissions := make([]*output.GitHubActionsPermission, 0)

	if role == nil || role.AssumeRolePolicyDocument.Statement == nil {
		return permissions, nil
	}

	// Convert role to ResourceRef
	roleRef, err := TransformRoleDLToResourceRef(role)
	if err != nil {
		return permissions, err
	}

	// Check each statement in the assume role policy
	for _, stmt := range *role.AssumeRolePolicyDocument.Statement {
		// Check if this is a GitHub Actions federated principal
		if !iam.IsGitHubActionsFederatedPrincipal(stmt.Principal) {
			continue
		}

		// Skip deny statements
		if strings.ToLower(stmt.Effect) != "allow" {
			continue
		}

		// Extract GitHub Actions subject patterns from conditions
		subjectPatterns := iam.ExtractGitHubActionsSubjectPatternsFromStatement(&stmt)
		if len(subjectPatterns) == 0 {
			continue
		}

		// Group patterns by repository
		repositories := iam.GroupSubjectPatternsByRepository(subjectPatterns)

		// Create permissions for each repository
		for fullRepoName, patterns := range repositories {
			// Parse org/repo from full name
			parts := strings.Split(fullRepoName, "/")
			if len(parts) < 2 {
				continue
			}

			org := parts[0]
			repo := strings.Join(parts[1:], "/") // Handle multi-level repos

			// Create Repository entity
			repository, err := CreateRepositoryFromGitHubSubject(org, repo)
			if err != nil {
				continue
			}

			// Create the permission
			perm, err := CreateGitHubActionsPermission(repository, roleRef, patterns, stmt.Condition)
			if err != nil {
				continue
			}

			permissions = append(permissions, perm)
		}
	}

	return permissions, nil
}
