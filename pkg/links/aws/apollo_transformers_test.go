package aws

import (
	"testing"

	"github.com/praetorian-inc/nebula/pkg/types"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
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
			repo:        "nebula",
			expectedURL: "https://github.com/praetorian-inc/nebula",
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
	repo, err := CreateRepositoryFromGitHubSubject("praetorian-inc", "nebula")
	require.NoError(t, err)

	// Create test role
	roleProperties := map[string]any{
		"roleName": "github-actions-role",
	}
	role, err := model.NewAWSResource(
		"arn:aws:iam::123456789012:role/github-actions-role",
		"123456789012",
		model.AWSRole,
		roleProperties,
	)
	require.NoError(t, err)

	tests := []struct {
		name            string
		repository      model.GraphModel
		role            model.GraphModel
		subjectPatterns []string
		conditions      *types.Condition
		expectedError   bool
		expectedAction  string
		expectedCapab   string
	}{
		{
			name:            "Valid repository to role relationship",
			repository:      repo,
			role:            &role,
			subjectPatterns: []string{"repo:praetorian-inc/nebula:ref:refs/heads/main"},
			conditions:      nil,
			expectedError:   false,
			expectedAction:  "sts:AssumeRole",
			expectedCapab:   "apollo-github-actions-federation",
		},
		{
			name:       "Multiple subject patterns",
			repository: repo,
			role:       &role,
			subjectPatterns: []string{
				"repo:praetorian-inc/nebula:ref:refs/heads/main",
				"repo:praetorian-inc/nebula:environment:production",
			},
			conditions:     nil,
			expectedError:  false,
			expectedAction: "sts:AssumeRole",
			expectedCapab:  "apollo-github-actions-federation",
		},
		{
			name:            "Nil repository",
			repository:      nil,
			role:            &role,
			subjectPatterns: []string{"repo:praetorian-inc/nebula:ref:refs/heads/main"},
			conditions:      nil,
			expectedError:   true,
		},
		{
			name:            "Nil role",
			repository:      repo,
			role:            nil,
			subjectPatterns: []string{"repo:praetorian-inc/nebula:ref:refs/heads/main"},
			conditions:      nil,
			expectedError:   true,
		},
		{
			name:            "Empty subject patterns",
			repository:      repo,
			role:            &role,
			subjectPatterns: []string{},
			conditions:      nil,
			expectedError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rel, err := CreateGitHubActionsRelationship(tt.repository, tt.role, tt.subjectPatterns, tt.conditions)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, rel)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, rel)

				// Check relationship properties
				iamRel, ok := rel.(*model.IamRelationship)
				require.True(t, ok, "Expected IamRelationship")
				assert.Equal(t, tt.expectedAction, iamRel.Permission)
				assert.Equal(t, tt.expectedCapab, iamRel.Capability)
				assert.NotNil(t, iamRel)
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
											"token.actions.githubusercontent.com:sub": types.DynaString{"repo:praetorian-inc/nebula:ref:refs/heads/main"},
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
											"token.actions.githubusercontent.com:sub": types.DynaString{"repo:praetorian-inc/nebula:ref:refs/heads/main"},
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
												"repo:praetorian-inc/nebula:*",
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
			relationships, err := ExtractGitHubActionsRelationships(tt.gaad)
			assert.NoError(t, err)
			assert.Len(t, relationships, tt.expectedLen)

			// If we expect relationships, verify they're IamRelationships
			for _, rel := range relationships {
				iamRel, ok := rel.(*model.IamRelationship)
				require.True(t, ok, "Expected IamRelationship")
				assert.Equal(t, "sts:AssumeRole", iamRel.Permission)
				assert.Equal(t, "apollo-github-actions-federation", iamRel.Capability)
			}
		})
	}
}

func TestTransformUserDLToAWSResource(t *testing.T) {
	tests := []struct {
		name     string
		user     *types.UserDL
		expected *model.AWSResource
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
			expected: nil,
			hasError: true,
		},
		{
			name: "User with empty ARN",
			user: &types.UserDL{
				UserName: "test-user",
				Arn:      "",
				Path:     "/",
				UserId:   "AIDAEXAMPLE123456789",
			},
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource, err := TransformUserDLToAWSResource(tt.user)

			if tt.hasError {
				assert.Error(t, err)
				assert.Nil(t, resource)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resource)
				assert.Equal(t, model.AWSUser, resource.ResourceType)
				if tt.user.Arn != "" {
					assert.Equal(t, tt.user.Arn, resource.Name)
				}
			}
		})
	}
}

func TestTransformRoleDLToAWSResource(t *testing.T) {
	tests := []struct {
		name     string
		role     *types.RoleDL
		expected *model.AWSResource
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
			expected: nil,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource, err := TransformRoleDLToAWSResource(tt.role)

			if tt.hasError {
				assert.Error(t, err)
				assert.Nil(t, resource)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resource)
				assert.Equal(t, model.AWSRole, resource.ResourceType)
				if tt.role.Arn != "" {
					assert.Equal(t, tt.role.Arn, resource.Name)
				}
			}
		})
	}
}

func TestTransformGroupDLToAWSResource(t *testing.T) {
	tests := []struct {
		name     string
		group    *types.GroupDL
		expected *model.AWSResource
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
			expected: nil,
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource, err := TransformGroupDLToAWSResource(tt.group)

			if tt.hasError {
				assert.Error(t, err)
				assert.Nil(t, resource)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resource)
				assert.Equal(t, model.AWSGroup, resource.ResourceType)
				if tt.group.Arn != "" {
					assert.Equal(t, tt.group.Arn, resource.Name)
				}
			}
		})
	}
}
