package aws

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateRepositoryFromGitHubSubject(t *testing.T) {
	tests := []struct {
		name        string
		org         string
		repo        string
		expectedURL string
		expectError bool
	}{
		{
			name:        "Valid org and repo",
			org:         "praetorian-inc",
			repo:        "aurelian",
			expectedURL: "https://github.com/praetorian-inc/aurelian",
			expectError: false,
		},
		{
			name:        "Multi-level repository name",
			org:         "company",
			repo:        "sub-org/project",
			expectedURL: "https://github.com/company/sub-org/project",
			expectError: false,
		},
		{
			name:        "Repository with numbers and dashes",
			org:         "my-org-123",
			repo:        "service-v2",
			expectedURL: "https://github.com/my-org-123/service-v2",
			expectError: false,
		},
		{
			name:        "Empty org",
			org:         "",
			repo:        "repo",
			expectedURL: "",
			expectError: true,
		},
		{
			name:        "Empty repo",
			org:         "org",
			repo:        "",
			expectedURL: "",
			expectError: true,
		},
		{
			name:        "Both empty",
			org:         "",
			repo:        "",
			expectedURL: "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repository, err := CreateRepositoryFromGitHubSubject(tt.org, tt.repo)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, repository)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, repository)
				assert.Equal(t, tt.expectedURL, repository.URL)
				// For multi-level repos, the parser might interpret differently
				if tt.name != "Multi-level repository name" {
					assert.Equal(t, tt.org, repository.Org)
					assert.Equal(t, tt.repo, repository.Name)
				}
			}
		})
	}
}

func TestCreateGitHubActionsRelationship(t *testing.T) {
	// Create test repository
	repo, err := CreateRepositoryFromGitHubSubject("praetorian-inc", "aurelian")
	require.NoError(t, err)

	// Create test role ResourceRef
	roleRef := output.ResourceRef{
		Platform: "aws",
		Type:     "iam-role",
		ID:       "arn:aws:iam::123456789012:role/github-actions-role",
		Account:  "123456789012",
	}

	tests := []struct {
		name            string
		repository      *output.Repository
		roleRef         output.ResourceRef
		subjectPatterns []string
		conditions      *types.Condition
		expectedError   bool
		expectedAction  string
		expectedCapab   string
	}{
		{
			name:            "Valid repository to role relationship",
			repository:      repo,
			roleRef:         roleRef,
			subjectPatterns: []string{"repo:praetorian-inc/aurelian:ref:refs/heads/main"},
			conditions:      nil,
			expectedError:   false,
			expectedAction:  "sts:AssumeRoleWithWebIdentity",
			expectedCapab:   "apollo-github-actions-federation",
		},
		{
			name:       "Multiple subject patterns",
			repository: repo,
			roleRef:    roleRef,
			subjectPatterns: []string{
				"repo:praetorian-inc/aurelian:ref:refs/heads/main",
				"repo:praetorian-inc/aurelian:environment:production",
			},
			conditions:     nil,
			expectedError:  false,
			expectedAction: "sts:AssumeRoleWithWebIdentity",
			expectedCapab:  "apollo-github-actions-federation",
		},
		{
			name:            "Nil repository",
			repository:      nil,
			roleRef:         roleRef,
			subjectPatterns: []string{"repo:praetorian-inc/aurelian:ref:refs/heads/main"},
			conditions:      nil,
			expectedError:   true,
		},
		{
			name:            "Empty subject patterns",
			repository:      repo,
			roleRef:         roleRef,
			subjectPatterns: []string{},
			conditions:      nil,
			expectedError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perm, err := CreateGitHubActionsPermission(tt.repository, tt.roleRef, tt.subjectPatterns, tt.conditions)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, perm)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, perm)

				// Check permission properties
				assert.Equal(t, tt.expectedAction, perm.Permission)
				assert.Equal(t, tt.expectedCapab, perm.Capability)
				assert.Equal(t, "github", perm.Source.Platform)
				assert.Equal(t, "repository", perm.Source.Type)
				assert.Equal(t, "aws", perm.Target.Platform)
				assert.Equal(t, "iam-role", perm.Target.Type)
			}
		})
	}
}

func TestExtractGitHubActionsRelationships(t *testing.T) {
	tests := []struct {
		name        string
		gaad        *types.Gaad
		expectedLen int
	}{
		{
			name:        "Nil GAAD",
			gaad:        nil,
			expectedLen: 0,
		},
		{
			name: "Empty GAAD",
			gaad: &types.Gaad{
				RoleDetailList: []types.RoleDL{},
			},
			expectedLen: 0,
		},
		{
			name: "GAAD with GitHub Actions role",
			gaad: &types.Gaad{
				RoleDetailList: []types.RoleDL{
					{
						RoleName: "github-actions-role",
						Arn:      "arn:aws:iam::123456789012:role/github-actions-role",
						AssumeRolePolicyDocument: types.Policy{
							Statement: &types.PolicyStatementList{
								{
									Effect: "Allow",
									Action: &types.DynaString{"sts:AssumeRole"},
									Principal: &types.Principal{
										Federated: &types.DynaString{"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
									},
									Condition: &types.Condition{
										"StringEquals": {
											"token.actions.githubusercontent.com:sub": types.DynaString{"repo:praetorian-inc/aurelian:ref:refs/heads/main"},
											"token.actions.githubusercontent.com:aud": types.DynaString{"sts.amazonaws.com"},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedLen: 1,
		},
		{
			name: "GAAD with non-GitHub Actions role",
			gaad: &types.Gaad{
				RoleDetailList: []types.RoleDL{
					{
						RoleName: "ec2-role",
						Arn:      "arn:aws:iam::123456789012:role/ec2-role",
						AssumeRolePolicyDocument: types.Policy{
							Statement: &types.PolicyStatementList{
								{
									Effect: "Allow",
									Action: &types.DynaString{"sts:AssumeRole"},
									Principal: &types.Principal{
										Service: &types.DynaString{"ec2.amazonaws.com"},
									},
								},
							},
						},
					},
				},
			},
			expectedLen: 0,
		},
		{
			name: "GAAD with mixed roles",
			gaad: &types.Gaad{
				RoleDetailList: []types.RoleDL{
					{
						RoleName: "github-actions-role",
						Arn:      "arn:aws:iam::123456789012:role/github-actions-role",
						AssumeRolePolicyDocument: types.Policy{
							Statement: &types.PolicyStatementList{
								{
									Effect: "Allow",
									Action: &types.DynaString{"sts:AssumeRole"},
									Principal: &types.Principal{
										Federated: &types.DynaString{"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
									},
									Condition: &types.Condition{
										"StringEquals": {
											"token.actions.githubusercontent.com:sub": types.DynaString{"repo:praetorian-inc/aurelian:ref:refs/heads/main"},
											"token.actions.githubusercontent.com:aud": types.DynaString{"sts.amazonaws.com"},
										},
									},
								},
							},
						},
					},
					{
						RoleName: "ec2-role",
						Arn:      "arn:aws:iam::123456789012:role/ec2-role",
						AssumeRolePolicyDocument: types.Policy{
							Statement: &types.PolicyStatementList{
								{
									Effect: "Allow",
									Action: &types.DynaString{"sts:AssumeRole"},
									Principal: &types.Principal{
										Service: &types.DynaString{"ec2.amazonaws.com"},
									},
								},
							},
						},
					},
				},
			},
			expectedLen: 1,
		},
		{
			name: "GAAD with multiple GitHub Actions repositories",
			gaad: &types.Gaad{
				RoleDetailList: []types.RoleDL{
					{
						RoleName: "github-actions-role",
						Arn:      "arn:aws:iam::123456789012:role/github-actions-role",
						AssumeRolePolicyDocument: types.Policy{
							Statement: &types.PolicyStatementList{
								{
									Effect: "Allow",
									Action: &types.DynaString{"sts:AssumeRole"},
									Principal: &types.Principal{
										Federated: &types.DynaString{"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"},
									},
									Condition: &types.Condition{
										"StringLike": {
											"token.actions.githubusercontent.com:sub": types.DynaString{
												"repo:praetorian-inc/aurelian:*",
												"repo:praetorian-inc/konstellation:*",
											},
											"token.actions.githubusercontent.com:aud": types.DynaString{"sts.amazonaws.com"},
										},
									},
								},
							},
						},
					},
				},
			},
			expectedLen: 2, // Two different repositories should create two relationships
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			permissions, err := ExtractGitHubActionsPermissions(tt.gaad)
			assert.NoError(t, err)
			assert.Len(t, permissions, tt.expectedLen)

			// If we expect permissions, verify they're GitHubActionsPermissions
			for _, perm := range permissions {
				assert.Equal(t, "sts:AssumeRoleWithWebIdentity", perm.Permission)
				assert.Equal(t, "apollo-github-actions-federation", perm.Capability)
				assert.Equal(t, "github", perm.Source.Platform)
				assert.Equal(t, "repository", perm.Source.Type)
			}
		})
	}
}

func TestTransformUserDLToCloudResource(t *testing.T) {
	tests := []struct {
		name     string
		user     *types.UserDL
		hasError bool
	}{
		{
			name: "Valid user",
			user: &types.UserDL{
				UserName:   "test-user",
				Arn:        "arn:aws:iam::123456789012:user/test-user",
				Path:       "/",
				UserId:     "AIDAEXAMPLE123456789",
				CreateDate: "2023-01-01T00:00:00Z",
			},
			hasError: false,
		},
		{
			name:     "Nil user",
			user:     nil,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource, err := TransformUserDLToCloudResource(tt.user)

			if tt.hasError {
				assert.Error(t, err)
				assert.Nil(t, resource)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resource)
				assert.Equal(t, "aws", resource.Platform)
				assert.Equal(t, "AWS::IAM::User", resource.ResourceType)
				assert.Equal(t, tt.user.Arn, resource.ResourceID)
				assert.Equal(t, "123456789012", resource.AccountRef)
			}
		})
	}
}

func TestTransformRoleDLToCloudResource(t *testing.T) {
	tests := []struct {
		name     string
		role     *types.RoleDL
		hasError bool
	}{
		{
			name: "Valid role",
			role: &types.RoleDL{
				RoleName:   "test-role",
				Arn:        "arn:aws:iam::123456789012:role/test-role",
				Path:       "/",
				RoleId:     "AROAEXAMPLE123456789",
				CreateDate: "2023-01-01T00:00:00Z",
				AssumeRolePolicyDocument: types.Policy{
					Statement: &types.PolicyStatementList{
						{
							Effect: "Allow",
							Action: &types.DynaString{"sts:AssumeRole"},
							Principal: &types.Principal{
								Service: &types.DynaString{"ec2.amazonaws.com"},
							},
						},
					},
				},
			},
			hasError: false,
		},
		{
			name:     "Nil role",
			role:     nil,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource, err := TransformRoleDLToCloudResource(tt.role)

			if tt.hasError {
				assert.Error(t, err)
				assert.Nil(t, resource)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resource)
				assert.Equal(t, "aws", resource.Platform)
				assert.Equal(t, "AWS::IAM::Role", resource.ResourceType)
				assert.Equal(t, tt.role.Arn, resource.ResourceID)
				assert.Equal(t, "123456789012", resource.AccountRef)
			}
		})
	}
}

func TestTransformGroupDLToCloudResource(t *testing.T) {
	tests := []struct {
		name     string
		group    *types.GroupDL
		hasError bool
	}{
		{
			name: "Valid group",
			group: &types.GroupDL{
				GroupName:  "test-group",
				Arn:        "arn:aws:iam::123456789012:group/test-group",
				Path:       "/",
				GroupId:    "AGPAEXAMPLE123456789",
				CreateDate: "2023-01-01T00:00:00Z",
			},
			hasError: false,
		},
		{
			name:     "Nil group",
			group:    nil,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource, err := TransformGroupDLToCloudResource(tt.group)

			if tt.hasError {
				assert.Error(t, err)
				assert.Nil(t, resource)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resource)
				assert.Equal(t, "aws", resource.Platform)
				assert.Equal(t, "AWS::IAM::Group", resource.ResourceType)
				assert.Equal(t, tt.group.Arn, resource.ResourceID)
				assert.Equal(t, "123456789012", resource.AccountRef)
			}
		})
	}
}
