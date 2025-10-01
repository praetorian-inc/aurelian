package aws

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	iam "github.com/praetorian-inc/nebula/pkg/iam/aws"
	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// TransformUserDLToAWSResource converts a UserDL to an AWSResource with AWSUser type
func TransformUserDLToAWSResource(user *types.UserDL) (*model.AWSResource, error) {
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

	awsResource, err := model.NewAWSResource(
		user.Arn,
		accountID,
		model.AWSUser,
		properties,
	)
	if err != nil {
		return nil, err
	}

	return &awsResource, nil
}

// TransformRoleDLToAWSResource converts a RoleDL to an AWSResource with AWSRole type
func TransformRoleDLToAWSResource(role *types.RoleDL) (*model.AWSResource, error) {
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

	awsResource, err := model.NewAWSResource(
		role.Arn,
		accountID,
		model.AWSRole,
		properties,
	)
	if err != nil {
		return nil, err
	}

	return &awsResource, nil
}

// TransformGroupDLToAWSResource converts a GroupDL to an AWSResource with AWSGroup type
func TransformGroupDLToAWSResource(group *types.GroupDL) (*model.AWSResource, error) {
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

	awsResource, err := model.NewAWSResource(
		group.Arn,
		accountID,
		model.AWSGroup,
		properties,
	)
	if err != nil {
		return nil, err
	}

	return &awsResource, nil
}

// TransformERDToAWSResource converts an EnrichedResourceDescription to an AWSResource
func TransformERDToAWSResource(erd *types.EnrichedResourceDescription) (*model.AWSResource, error) {
	if erd == nil {
		return nil, fmt.Errorf("enriched resource description cannot be nil")
	}

	// Convert TypeName to CloudResourceType
	cloudResourceType := model.CloudResourceType(erd.TypeName)

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

	awsResource, err := model.NewAWSResource(
		erd.Arn.String(),
		erd.AccountId,
		cloudResourceType,
		properties,
	)
	if err != nil {
		return nil, err
	}

	return &awsResource, nil
}

// CreateServicePrincipalResource creates an AWSResource for service principals
func CreateServicePrincipalResource(principalString string) (*model.AWSResource, error) {
	serviceName := principalString
	accountID := "aws" // Service principals are AWS-owned

	// Extract service name from ARN format if needed
	if strings.HasPrefix(principalString, "arn:aws:iam::aws:service/") {
		serviceName = strings.TrimPrefix(principalString, "arn:aws:iam::aws:service/")
	}

	properties := map[string]any{
		"name":     serviceName,
		"fullName": principalString,
		"type":     "service",
	}

	// Create a generic AWS resource for service principals
	// We don't have a specific CloudResourceType for services, so we'll use a generic approach
	return &model.AWSResource{
		CloudResource: model.CloudResource{
			Key:          fmt.Sprintf("#awsresource#%s#%s", accountID, principalString),
			Name:         principalString,
			DisplayName:  serviceName,
			Provider:     "aws",
			Properties:   properties,
			ResourceType: model.CloudResourceType("AWS::IAM::ServicePrincipal"), // Custom type
			AccountRef:   accountID,
			Labels:       []string{"AWSResource", "Service", "Principal", "Resource"},
		},
	}, nil
}

// CreateGenericPrincipalResource creates an AWSResource for other principal types
func CreateGenericPrincipalResource(principalString string) (*model.AWSResource, error) {
	principalName := principalString

	// Try to extract a short name from ARN
	if strings.HasPrefix(principalString, "arn:") {
		parts := strings.Split(principalString, "/")
		if len(parts) > 1 {
			principalName = parts[len(parts)-1]
		}
	}

	// Extract account ID if it's an ARN
	accountID := ""
	if strings.HasPrefix(principalString, "arn:") {
		if parsedArn, err := arn.Parse(principalString); err == nil {
			accountID = parsedArn.AccountID
		}
	}

	properties := map[string]any{
		"name": principalName,
	}

	return &model.AWSResource{
		CloudResource: model.CloudResource{
			Key:          fmt.Sprintf("#awsresource#%s#%s", accountID, principalString),
			Name:         principalString,
			DisplayName:  principalName,
			Provider:     "aws",
			Properties:   properties,
			ResourceType: model.CloudResourceType("AWS::IAM::Principal"), // Generic principal type
			AccountRef:   accountID,
			Labels:       []string{"AWSResource", "Principal"},
		},
	}, nil
}

// TransformResultToRelationship converts an iam.FullResult to a Tabularium IamPermission relationship
func TransformResultToRelationship(result iam.FullResult) (model.GraphRelationship, error) {
	// Handle Principal (Source)
	var source model.GraphModel
	var err error

	switch p := result.Principal.(type) {
	case *types.UserDL:
		source, err = TransformUserDLToAWSResource(p)
		if err != nil {
			return nil, fmt.Errorf("failed to transform user: %w", err)
		}
	case *types.RoleDL:
		source, err = TransformRoleDLToAWSResource(p)
		if err != nil {
			return nil, fmt.Errorf("failed to transform role: %w", err)
		}
	case *types.GroupDL:
		source, err = TransformGroupDLToAWSResource(p)
		if err != nil {
			return nil, fmt.Errorf("failed to transform group: %w", err)
		}
	case string:
		// Handle service principals
		if strings.Contains(p, "amazonaws.com") || strings.Contains(p, "aws:service") {
			source, err = CreateServicePrincipalResource(p)
		} else {
			source, err = CreateGenericPrincipalResource(p)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to create principal resource: %w", err)
		}
	default:
		return nil, fmt.Errorf("unknown principal type: %T", p)
	}

	// Handle Resource (Target)
	if result.Resource == nil {
		return nil, fmt.Errorf("nil resource")
	}

	target, err := TransformERDToAWSResource(result.Resource)
	if err != nil {
		return nil, fmt.Errorf("failed to transform resource: %w", err)
	}

	// Create the IAM permission relationship
	rel := model.NewIamRelationship(source, target, result.Action)

	// Add evaluation details to the relationship
	rel.Capability = "apollo-iam-analysis"
	rel.Created = model.Now()
	rel.Visited = model.Now()

	return rel, nil
}

// CreateRepositoryFromGitHubSubject creates a Repository entity from GitHub Actions subject claims
func CreateRepositoryFromGitHubSubject(org, repo string) (*model.Repository, error) {
	if org == "" || repo == "" {
		return nil, fmt.Errorf("org and repo cannot be empty")
	}

	// Use Tabularium NewRepository constructor which handles all validation and processing
	repoURL := fmt.Sprintf("https://github.com/%s/%s", org, repo)
	repository := model.NewRepository(repoURL)

	// NewRepository automatically:
	// - Calls Defaulted() for BaseAsset setup
	// - Runs all processing hooks via registry.CallHooks()
	// - Sets URL, Org, Name fields correctly
	// - Validates the repository

	if repository.URL == "" {
		return nil, fmt.Errorf("failed to create repository from %s/%s", org, repo)
	}

	return &repository, nil
}

// CreateGitHubActionsRelationship creates a Repository→Role relationship with GitHub Actions constraints
func CreateGitHubActionsRelationship(repository model.GraphModel, role model.GraphModel, subjectPatterns []string, conditions *types.Condition) (model.GraphRelationship, error) {
	if repository == nil || role == nil {
		return nil, fmt.Errorf("repository and role cannot be nil")
	}

	if len(subjectPatterns) == 0 {
		return nil, fmt.Errorf("subject patterns cannot be empty")
	}

	// Create the assume role relationship using IamRelationship
	rel := model.NewIamRelationship(repository, role, "sts:AssumeRole")
	rel.Capability = "apollo-github-actions-federation"
	rel.Created = model.Now()
	rel.Visited = model.Now()

	// For now, store additional GitHub Actions info in the key for traceability
	// TODO: Extend IamRelationship or create GitHubActionsRelationship for better property support
	rel.Key = fmt.Sprintf("%s#GitHub-Actions#%s", repository.GetKey(), role.GetKey())

	return rel, nil
}

// ExtractGitHubActionsRelationships extracts all GitHub Actions Repository→Role relationships from GAAD data
func ExtractGitHubActionsRelationships(gaad *types.Gaad) ([]model.GraphRelationship, error) {
	relationships := make([]model.GraphRelationship, 0)

	if gaad == nil {
		return relationships, nil
	}

	// Process all roles for GitHub Actions assume role policies
	for _, role := range gaad.RoleDetailList {
		repoRelationships, err := extractGitHubActionsRelationshipsFromRole(&role)
		if err != nil {
			// Log error but continue processing
			continue
		}
		relationships = append(relationships, repoRelationships...)
	}

	return relationships, nil
}

// extractGitHubActionsRelationshipsFromRole extracts GitHub Actions relationships from a single role
func extractGitHubActionsRelationshipsFromRole(role *types.RoleDL) ([]model.GraphRelationship, error) {
	relationships := make([]model.GraphRelationship, 0)

	if role == nil || role.AssumeRolePolicyDocument.Statement == nil {
		return relationships, nil
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

		// Create relationships for each repository
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

			// Create Role entity
			roleModel, err := TransformRoleDLToAWSResource(role)
			if err != nil {
				continue
			}

			// Create the relationship
			rel, err := CreateGitHubActionsRelationship(repository, roleModel, patterns, stmt.Condition)
			if err != nil {
				continue
			}

			relationships = append(relationships, rel)
		}
	}

	return relationships, nil
}
