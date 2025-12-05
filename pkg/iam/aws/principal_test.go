package aws

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/praetorian-inc/nebula/pkg/types"
)

func TestExtractPrincipalsLocations(t *testing.T) {
	tests := []struct {
		name        string
		description string
		policyJSON  string
		want        []types.Principal
		wantErr     bool
	}{
		{
			name:        "IAM Role Trust Policy",
			description: "Trust policy allowing service and AWS account access",
			policyJSON: `{
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "lambda.amazonaws.com",
                        "AWS": [
                            "arn:aws:iam::111122223333:root",
                            "arn:aws:iam::444455556666:role/admin-role"
                        ]
                    },
                    "Action": "sts:AssumeRole"
                }]
            }`,
			want: []types.Principal{
				{
					Service: types.NewDynaString([]string{"lambda.amazonaws.com"}),
				},
				{
					AWS: types.NewDynaString([]string{
						"arn:aws:iam::111122223333:root",
						"arn:aws:iam::444455556666:role/admin-role",
					}),
				},
			},
			wantErr: false,
		},
		{
			name:        "S3 Bucket Policy",
			description: "Resource-based policy with cross-account access and conditions",
			policyJSON: `{
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "CrossAccountAccess",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::111122223333:root"
                    },
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::mybucket/*",
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalOrgID": "o-abcdef123456",
                            "aws:SourceAccount": "111122223333"
                        }
                    }
                }]
            }`,
			want: []types.Principal{
				{
					AWS: types.NewDynaString([]string{"arn:aws:iam::111122223333:root"}),
				},
				{
					AWS: types.NewDynaString([]string{"o-abcdef123456"}),
				},
				{
					AWS: types.NewDynaString([]string{"111122223333"}),
				},
			},
			wantErr: false,
		},
		{
			name:        "KMS Key Policy",
			description: "Key policy allowing service and specific roles",
			policyJSON: `{
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "Enable IAM User Permissions",
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::111122223333:root"
                    },
                    "Action": "kms:*",
                    "Resource": "*"
                },
                {
                    "Sid": "Allow CloudWatch Logs",
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "logs.amazonaws.com"
                    },
                    "Action": [
                        "kms:Encrypt*",
                        "kms:Decrypt*",
                        "kms:ReEncrypt*",
                        "kms:GenerateDataKey*",
                        "kms:Describe*"
                    ],
                    "Resource": "*",
                    "Condition": {
                        "ArnLike": {
                            "aws:SourceArn": "arn:aws:logs:region:111122223333:*"
                        }
                    }
                }]
            }`,
			want: []types.Principal{
				{
					AWS: types.NewDynaString([]string{"arn:aws:iam::111122223333:root"}),
				},
				{
					Service: types.NewDynaString([]string{"logs.amazonaws.com"}),
				},
				{
					AWS: types.NewDynaString([]string{"arn:aws:logs:region:111122223333:*"}),
				},
			},
			wantErr: false,
		},
		{
			name:        "SQS Queue Policy",
			description: "Queue policy allowing SNS service and cross-account access",
			policyJSON: `{
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "sns.amazonaws.com",
                        "AWS": "arn:aws:iam::111122223333:root"
                    },
                    "Action": "sqs:SendMessage",
                    "Resource": "arn:aws:sqs:region:444455556666:queue-name",
                    "Condition": {
                        "ArnLike": {
                            "aws:SourceArn": "arn:aws:sns:region:111122223333:topic-name"
                        }
                    }
                }]
            }`,
			want: []types.Principal{
				{
					Service: types.NewDynaString([]string{"sns.amazonaws.com"}),
				},
				{
					AWS: types.NewDynaString([]string{"arn:aws:iam::111122223333:root"}),
				},
				{
					AWS: types.NewDynaString([]string{"arn:aws:sns:region:111122223333:topic-name"}),
				},
			},
			wantErr: false,
		},
		{
			name:        "Lambda Function Policy",
			description: "Function policy allowing S3 and API Gateway triggers",
			policyJSON: `{
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {
                        "Service": ["s3.amazonaws.com", "apigateway.amazonaws.com"]
                    },
                    "Action": "lambda:InvokeFunction",
                    "Resource": "arn:aws:lambda:region:111122223333:function:function-name",
                    "Condition": {
                        "StringEquals": {
                            "aws:SourceAccount": "111122223333"
                        },
                        "ArnLike": {
                            "aws:SourceArn": [
                                "arn:aws:s3:::bucket-name",
                                "arn:aws:execute-api:region:111122223333:api-id/*"
                            ]
                        }
                    }
                }]
            }`,
			want: []types.Principal{
				{
					Service: types.NewDynaString([]string{
						"s3.amazonaws.com",
						"apigateway.amazonaws.com",
					}),
				},
				{
					AWS: types.NewDynaString([]string{"111122223333"}),
				},
				{
					AWS: types.NewDynaString([]string{
						"arn:aws:s3:::bucket-name",
						"arn:aws:execute-api:region:111122223333:api-id/*",
					}),
				},
			},
			wantErr: false,
		},
		{
			name:        "Federated Identity Policy",
			description: "Policy for web identity federation",
			policyJSON: `{
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {
                        "Federated": ["cognito-identity.amazonaws.com", "accounts.google.com"]
                    },
                    "Action": "sts:AssumeRoleWithWebIdentity",
                    "Condition": {
                        "StringEquals": {
                            "cognito-identity.amazonaws.com:aud": "us-east-1:12345678-1234-1234-1234-123456789012"
                        }
                    }
                }]
            }`,
			want: []types.Principal{
				{
					Federated: types.NewDynaString([]string{
						"cognito-identity.amazonaws.com",
						"accounts.google.com",
					}),
				},
			},
			wantErr: false,
		},
		{
			name:        "Secrets Manager Policy",
			description: "Secret policy with service principal and cross-account access",
			policyJSON: `{
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::111122223333:role/service-role",
                        "Service": "lambda.amazonaws.com"
                    },
                    "Action": "secretsmanager:GetSecretValue",
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {
                            "aws:PrincipalServiceName": "lambda.amazonaws.com",
                            "aws:SourceAccount": "111122223333"
                        }
                    }
                }]
            }`,
			want: []types.Principal{
				{
					AWS: types.NewDynaString([]string{"arn:aws:iam::111122223333:role/service-role"}),
				},
				{
					Service: types.NewDynaString([]string{"lambda.amazonaws.com"}),
				},
				{
					AWS: types.NewDynaString([]string{"111122223333"}),
				},
			},
			wantErr: false,
		},
		{
			name:        "CloudWatch Logs Resource Policy",
			description: "Log policy allowing cross-account and service access",
			policyJSON: `{
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": [
                            "arn:aws:iam::111122223333:root",
                            "arn:aws:iam::444455556666:root"
                        ],
                        "Service": ["vpc-flow-logs.amazonaws.com", "delivery.logs.amazonaws.com"]
                    },
                    "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                    "Resource": "arn:aws:logs:region:123456789012:log-group:*",
                    "Condition": {
                        "StringEquals": {
                            "aws:SourceAccount": ["111122223333", "444455556666"]
                        }
                    }
                }]
            }`,
			want: []types.Principal{
				{
					AWS: types.NewDynaString([]string{
						"arn:aws:iam::111122223333:root",
						"arn:aws:iam::444455556666:root",
					}),
				},
				{
					Service: types.NewDynaString([]string{
						"vpc-flow-logs.amazonaws.com",
						"delivery.logs.amazonaws.com",
					}),
				},
				{
					AWS: types.NewDynaString([]string{
						"111122223333",
						"444455556666",
					}),
				},
			},
			wantErr: false,
		},
		{
			name:        "NotPrincipal Policy",
			description: "Policy using NotPrincipal to deny specific identities",
			policyJSON: `{
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "NotPrincipal": {
                        "AWS": [
                            "arn:aws:iam::111122223333:role/blocked-role",
                            "arn:aws:iam::444455556666:user/blocked-user"
                        ],
                        "Service": "bad.service.amazonaws.com"
                    },
                    "Action": "*",
                    "Resource": "*"
                }]
            }`,
			want: []types.Principal{
				{
					AWS: types.NewDynaString([]string{
						"arn:aws:iam::111122223333:role/blocked-role",
						"arn:aws:iam::444455556666:user/blocked-user",
					}),
				},
				{
					Service: types.NewDynaString([]string{"bad.service.amazonaws.com"}),
				},
			},
			wantErr: false,
		},
		{
			name:        "Policy with Canonical User",
			description: "S3 bucket policy using canonical user ID",
			policyJSON: `{
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {
                        "CanonicalUser": "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be"
                    },
                    "Action": [
                        "s3:GetObject",
                        "s3:PutObject"
                    ],
                    "Resource": "arn:aws:s3:::mybucket/*"
                }]
            }`,
			want: []types.Principal{
				{
					CanonicalUser: types.NewDynaString([]string{
						"79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be",
					}),
				},
			},
			wantErr: false,
		},
		{
			name:        "role is the resource",
			description: "Policy where the role is the resource",
			policyJSON: `
			{
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Action": [
                                    "sts:AssumeRole"
                                ],
                                "Resource": "arn:aws:iam::*:role/praetorian-readonly",
                                "Effect": "Allow"
                            }
                        ]
                    }
            `,
			want: []types.Principal{
				{
					AWS: types.NewDynaString([]string{"arn:aws:iam::*:role/praetorian-readonly"}),
				},
			},
			wantErr: false,
		},
	}

	// Helper function to normalize and sort principals for comparison
	normalizePrincipals := func(principals []types.Principal) []types.Principal {
		// Create a deep copy to avoid modifying original
		normalized := make([]types.Principal, len(principals))
		for i, p := range principals {
			normalized[i] = types.Principal{
				AWS:           p.AWS,
				Service:       p.Service,
				Federated:     p.Federated,
				CanonicalUser: p.CanonicalUser,
			}

			// Sort values within each DynaString if present
			if p.AWS != nil && len(*p.AWS) > 1 {
				sorted := make([]string, len(*p.AWS))
				copy(sorted, *p.AWS)
				sort.Strings(sorted)
				normalized[i].AWS = types.NewDynaString(sorted)
			}
			if p.Service != nil && len(*p.Service) > 1 {
				sorted := make([]string, len(*p.Service))
				copy(sorted, *p.Service)
				sort.Strings(sorted)
				normalized[i].Service = types.NewDynaString(sorted)
			}
			if p.Federated != nil && len(*p.Federated) > 1 {
				sorted := make([]string, len(*p.Federated))
				copy(sorted, *p.Federated)
				sort.Strings(sorted)
				normalized[i].Federated = types.NewDynaString(sorted)
			}
			if p.CanonicalUser != nil && len(*p.CanonicalUser) > 1 {
				sorted := make([]string, len(*p.CanonicalUser))
				copy(sorted, *p.CanonicalUser)
				sort.Strings(sorted)
				normalized[i].CanonicalUser = types.NewDynaString(sorted)
			}
		}

		// Sort principals based on their type and first value
		sort.Slice(normalized, func(i, j int) bool {
			pi, pj := normalized[i], normalized[j]

			// Get principal type and first value for each principal
			var typeI, valI, typeJ, valJ string

			if pi.AWS != nil {
				typeI = "AWS"
				valI = (*pi.AWS)[0]
			} else if pi.Service != nil {
				typeI = "Service"
				valI = (*pi.Service)[0]
			} else if pi.Federated != nil {
				typeI = "Federated"
				valI = (*pi.Federated)[0]
			} else if pi.CanonicalUser != nil {
				typeI = "CanonicalUser"
				valI = (*pi.CanonicalUser)[0]
			}

			if pj.AWS != nil {
				typeJ = "AWS"
				valJ = (*pj.AWS)[0]
			} else if pj.Service != nil {
				typeJ = "Service"
				valJ = (*pj.Service)[0]
			} else if pj.Federated != nil {
				typeJ = "Federated"
				valJ = (*pj.Federated)[0]
			} else if pj.CanonicalUser != nil {
				typeJ = "CanonicalUser"
				valJ = (*pj.CanonicalUser)[0]
			}

			// Sort by type first, then by value
			if typeI != typeJ {
				return typeI < typeJ
			}
			return valI < valJ
		})

		return normalized
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pol, err := types.NewPolicyFromJSON([]byte(tt.policyJSON))
			if err != nil {
				t.Errorf("Error unmarshalling policy JSON: %v", err)
			}

			got, err := ExtractPrincipals(pol)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractPrincipals() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if !reflect.DeepEqual(normalizePrincipals(got), normalizePrincipals(tt.want)) {
				gotJson, _ := json.Marshal(got)
				wantJson, _ := json.Marshal(tt.want)
				t.Errorf("ExtractPrincipals() = %v, want %v", string(gotJson), string(wantJson))
			}
		})
	}
}
func TestIsAWSPrincipal(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want bool
	}{
		{
			name: "Valid IAM ARN",
			id:   "arn:aws:iam::123456789012:role/example-role",
			want: true,
		},
		{
			name: "Valid STS ARN",
			id:   "arn:aws:sts::123456789012:assumed-role/example-role/example-session",
			want: true,
		},
		{
			name: "Valid Service-linked role ARN",
			id:   "arn:aws:service-role/example-service-role",
			want: true,
		},
		{
			name: "Valid Account Root",
			id:   "arn:aws:iam::123456789012:root",
			want: true,
		},
		{
			name: "Valid IAM User ID",
			id:   "AIDAEXAMPLEUSERID",
			want: true,
		},
		{
			name: "Valid IAM Role ID",
			id:   "AROAEXAMPLEROLEID",
			want: true,
		},
		{
			name: "Valid IAM Group ID",
			id:   "AGPAEXAMPLEGROUPID",
			want: true,
		},
		{
			name: "Valid Account ID",
			id:   "123456789012",
			want: true,
		},
		{
			name: "Invalid ARN",
			id:   "arn:aws:s3:::example-bucket",
			want: false,
		},
		{
			name: "Invalid ID",
			id:   "invalid-id",
			want: false,
		},
		{
			name: "Valid Account Root Pattern",
			id:   "arn:aws:iam::123456789012:root",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAWSPrincipal(tt.id); got != tt.want {
				t.Errorf("IsAWSPrincipal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractGitHubActionsPrincipals(t *testing.T) {
	tests := []struct {
		name       string
		conditions *types.Condition
		want       []types.Principal
	}{
		{
			name: "GitHub Actions single subject claim",
			conditions: &types.Condition{
				"StringEquals": {
					GitHubActionsSubjectKey:   types.DynaString{"repo:praetorian-inc/nebula:ref:refs/heads/main"},
					GitHubActionsAudienceKey: types.DynaString{"sts.amazonaws.com"},
				},
			},
			want: []types.Principal{
				{
					Federated: types.NewDynaString([]string{"repo:praetorian-inc/nebula:ref:refs/heads/main"}),
				},
			},
		},
		{
			name: "GitHub Actions multiple subject claims",
			conditions: &types.Condition{
				"StringEquals": {
					GitHubActionsSubjectKey: types.DynaString{
						"repo:praetorian-inc/nebula:ref:refs/heads/main",
						"repo:praetorian-inc/nebula:environment:production",
					},
					GitHubActionsAudienceKey: types.DynaString{"sts.amazonaws.com"},
				},
			},
			want: []types.Principal{
				{
					Federated: types.NewDynaString([]string{
						"repo:praetorian-inc/nebula:ref:refs/heads/main",
						"repo:praetorian-inc/nebula:environment:production",
					}),
				},
			},
		},
		{
			name: "GitHub Actions wildcard subject claim",
			conditions: &types.Condition{
				"StringLike": {
					GitHubActionsSubjectKey:   types.DynaString{"repo:praetorian-inc/nebula:*"},
					GitHubActionsAudienceKey: types.DynaString{"sts.amazonaws.com"},
				},
			},
			want: []types.Principal{
				{
					Federated: types.NewDynaString([]string{"repo:praetorian-inc/nebula:*"}),
				},
			},
		},
		{
			name:       "No GitHub Actions conditions",
			conditions: &types.Condition{
				"StringEquals": {
					"aws:PrincipalAccount": types.DynaString{"123456789012"},
				},
			},
			want: []types.Principal{},
		},
		{
			name:       "Nil conditions",
			conditions: nil,
			want:       []types.Principal{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractGitHubActionsPrincipals(tt.conditions)
			if !reflect.DeepEqual(got, tt.want) {
				gotJSON, _ := json.Marshal(got)
				wantJSON, _ := json.Marshal(tt.want)
				t.Errorf("extractGitHubActionsPrincipals() = %v, want %v", string(gotJSON), string(wantJSON))
			}
		})
	}
}

func TestParseGitHubSubjectClaim(t *testing.T) {
	tests := []struct {
		name              string
		subject           string
		want              *GitHubSubjectClaim
		wantErr           bool
		wantErrContains   string
	}{
		{
			name:    "Branch reference",
			subject: "repo:praetorian-inc/nebula:ref:refs/heads/main",
			want: &GitHubSubjectClaim{
				Original:     "repo:praetorian-inc/nebula:ref:refs/heads/main",
				Org:          "praetorian-inc",
				Repo:         "nebula",
				FullRepoName: "praetorian-inc/nebula",
				Context:      "ref:refs/heads/main",
				ContextType:  "ref",
				ContextValue: "refs/heads/main",
			},
			wantErr: false,
		},
		{
			name:    "Environment deployment",
			subject: "repo:praetorian-inc/nebula:environment:production",
			want: &GitHubSubjectClaim{
				Original:     "repo:praetorian-inc/nebula:environment:production",
				Org:          "praetorian-inc",
				Repo:         "nebula",
				FullRepoName: "praetorian-inc/nebula",
				Context:      "environment:production",
				ContextType:  "environment",
				ContextValue: "production",
			},
			wantErr: false,
		},
		{
			name:    "Pull request",
			subject: "repo:praetorian-inc/nebula:pull_request",
			want: &GitHubSubjectClaim{
				Original:     "repo:praetorian-inc/nebula:pull_request",
				Org:          "praetorian-inc",
				Repo:         "nebula",
				FullRepoName: "praetorian-inc/nebula",
				Context:      "pull_request",
				ContextType:  "pull_request",
				ContextValue: "pull_request",
			},
			wantErr: false,
		},
		{
			name:    "Actor specific",
			subject: "repo:praetorian-inc/nebula:actor:username",
			want: &GitHubSubjectClaim{
				Original:     "repo:praetorian-inc/nebula:actor:username",
				Org:          "praetorian-inc",
				Repo:         "nebula",
				FullRepoName: "praetorian-inc/nebula",
				Context:      "actor:username",
				ContextType:  "actor",
				ContextValue: "username",
			},
			wantErr: false,
		},
		{
			name:    "Wildcard context",
			subject: "repo:praetorian-inc/nebula:*",
			want: &GitHubSubjectClaim{
				Original:     "repo:praetorian-inc/nebula:*",
				Org:          "praetorian-inc",
				Repo:         "nebula",
				FullRepoName: "praetorian-inc/nebula",
				Context:      "*",
				ContextType:  "*",
				ContextValue: "*",
			},
			wantErr: false,
		},
		{
			name:    "Multi-level repository",
			subject: "repo:organization/sub-org/repo-name:ref:refs/heads/main",
			want: &GitHubSubjectClaim{
				Original:     "repo:organization/sub-org/repo-name:ref:refs/heads/main",
				Org:          "organization",
				Repo:         "sub-org/repo-name",
				FullRepoName: "organization/sub-org/repo-name",
				Context:      "ref:refs/heads/main",
				ContextType:  "ref",
				ContextValue: "refs/heads/main",
			},
			wantErr: false,
		},
		{
			name:    "Tag reference",
			subject: "repo:praetorian-inc/nebula:ref:refs/tags/v1.0.0",
			want: &GitHubSubjectClaim{
				Original:     "repo:praetorian-inc/nebula:ref:refs/tags/v1.0.0",
				Org:          "praetorian-inc",
				Repo:         "nebula",
				FullRepoName: "praetorian-inc/nebula",
				Context:      "ref:refs/tags/v1.0.0",
				ContextType:  "ref",
				ContextValue: "refs/tags/v1.0.0",
			},
			wantErr: false,
		},
		{
			name:            "Empty subject",
			subject:         "",
			want:            nil,
			wantErr:         true,
			wantErrContains: "empty subject claim",
		},
		{
			name:            "Invalid format - no repo prefix",
			subject:         "invalid:praetorian-inc/nebula:ref:refs/heads/main",
			want:            nil,
			wantErr:         true,
			wantErrContains: "must start with 'repo:'",
		},
		{
			name:            "Invalid format - missing org/repo separator",
			subject:         "repo:praetorian-inc-nebula:ref:refs/heads/main",
			want:            nil,
			wantErr:         true,
			wantErrContains: "must contain org/repo",
		},
		{
			name:            "Invalid format - missing repository part",
			subject:         "repo:",
			want:            nil,
			wantErr:         true,
			wantErrContains: "must contain org/repo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseGitHubSubjectClaim(tt.subject)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseGitHubSubjectClaim() expected error but got none")
					return
				}
				if tt.wantErrContains != "" && !strings.Contains(err.Error(), tt.wantErrContains) {
					t.Errorf("ParseGitHubSubjectClaim() error = %v, want error containing %v", err, tt.wantErrContains)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseGitHubSubjectClaim() unexpected error = %v", err)
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseGitHubSubjectClaim() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestExtractRepositoriesFromConditions(t *testing.T) {
	tests := []struct {
		name       string
		conditions *types.Condition
		want       map[string][]string
		wantErr    bool
	}{
		{
			name: "Single repository with branch",
			conditions: &types.Condition{
				"StringEquals": {
					GitHubActionsSubjectKey:   types.DynaString{"repo:praetorian-inc/nebula:ref:refs/heads/main"},
					GitHubActionsAudienceKey: types.DynaString{"sts.amazonaws.com"},
				},
			},
			want: map[string][]string{
				"praetorian-inc/nebula": {"repo:praetorian-inc/nebula:ref:refs/heads/main"},
			},
			wantErr: false,
		},
		{
			name: "Single repository with multiple contexts",
			conditions: &types.Condition{
				"StringEquals": {
					GitHubActionsSubjectKey: types.DynaString{
						"repo:praetorian-inc/nebula:ref:refs/heads/main",
						"repo:praetorian-inc/nebula:environment:production",
						"repo:praetorian-inc/nebula:*",
					},
					GitHubActionsAudienceKey: types.DynaString{"sts.amazonaws.com"},
				},
			},
			want: map[string][]string{
				"praetorian-inc/nebula": {
					"repo:praetorian-inc/nebula:ref:refs/heads/main",
					"repo:praetorian-inc/nebula:environment:production",
					"repo:praetorian-inc/nebula:*",
				},
			},
			wantErr: false,
		},
		{
			name: "Multiple repositories",
			conditions: &types.Condition{
				"StringEquals": {
					GitHubActionsSubjectKey: types.DynaString{
						"repo:praetorian-inc/nebula:ref:refs/heads/main",
						"repo:praetorian-inc/tabularium:environment:production",
						"repo:organization/other-repo:*",
					},
					GitHubActionsAudienceKey: types.DynaString{"sts.amazonaws.com"},
				},
			},
			want: map[string][]string{
				"praetorian-inc/nebula":     {"repo:praetorian-inc/nebula:ref:refs/heads/main"},
				"praetorian-inc/tabularium": {"repo:praetorian-inc/tabularium:environment:production"},
				"organization/other-repo":   {"repo:organization/other-repo:*"},
			},
			wantErr: false,
		},
		{
			name: "Multi-level repository names",
			conditions: &types.Condition{
				"StringLike": {
					GitHubActionsSubjectKey: types.DynaString{
						"repo:org/sub-org/repo-name:ref:refs/heads/main",
						"repo:org/sub-org/repo-name:environment:staging",
					},
					GitHubActionsAudienceKey: types.DynaString{"sts.amazonaws.com"},
				},
			},
			want: map[string][]string{
				"org/sub-org/repo-name": {
					"repo:org/sub-org/repo-name:ref:refs/heads/main",
					"repo:org/sub-org/repo-name:environment:staging",
				},
			},
			wantErr: false,
		},
		{
			name: "No GitHub Actions conditions",
			conditions: &types.Condition{
				"StringEquals": {
					"aws:PrincipalAccount": types.DynaString{"123456789012"},
				},
			},
			want:    map[string][]string{},
			wantErr: false,
		},
		{
			name:       "Nil conditions",
			conditions: nil,
			want:       map[string][]string{},
			wantErr:    false,
		},
		{
			name: "Invalid subject claims ignored",
			conditions: &types.Condition{
				"StringEquals": {
					GitHubActionsSubjectKey: types.DynaString{
						"repo:praetorian-inc/nebula:ref:refs/heads/main", // Valid
						"invalid:format:here",                            // Invalid - should be ignored
						"repo:another-org/repo:environment:prod",         // Valid
					},
					GitHubActionsAudienceKey: types.DynaString{"sts.amazonaws.com"},
				},
			},
			want: map[string][]string{
				"praetorian-inc/nebula": {"repo:praetorian-inc/nebula:ref:refs/heads/main"},
				"another-org/repo":      {"repo:another-org/repo:environment:prod"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractRepositoriesFromConditions(tt.conditions)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractRepositoriesFromConditions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !reflect.DeepEqual(got, tt.want) {
				gotJSON, _ := json.Marshal(got)
				wantJSON, _ := json.Marshal(tt.want)
				t.Errorf("ExtractRepositoriesFromConditions() = %v, want %v", string(gotJSON), string(wantJSON))
			}
		})
	}
}

func TestIsGitHubActionsFederatedPrincipal(t *testing.T) {
	tests := []struct {
		name      string
		principal *types.Principal
		want      bool
	}{
		{
			name: "Valid GitHub Actions federated principal",
			principal: &types.Principal{
				Federated: types.NewDynaString([]string{"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"}),
			},
			want: true,
		},
		{
			name: "GitHub Actions provider in list",
			principal: &types.Principal{
				Federated: types.NewDynaString([]string{
					"cognito-identity.amazonaws.com",
					"arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com",
				}),
			},
			want: true,
		},
		{
			name: "Non-GitHub Actions federated principal",
			principal: &types.Principal{
				Federated: types.NewDynaString([]string{"cognito-identity.amazonaws.com"}),
			},
			want: false,
		},
		{
			name: "AWS principal",
			principal: &types.Principal{
				AWS: types.NewDynaString([]string{"arn:aws:iam::123456789012:root"}),
			},
			want: false,
		},
		{
			name: "Service principal",
			principal: &types.Principal{
				Service: types.NewDynaString([]string{"lambda.amazonaws.com"}),
			},
			want: false,
		},
		{
			name:      "Nil principal",
			principal: nil,
			want:      false,
		},
		{
			name:      "Principal with nil Federated",
			principal: &types.Principal{},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsGitHubActionsFederatedPrincipal(tt.principal)
			if got != tt.want {
				t.Errorf("IsGitHubActionsFederatedPrincipal() = %v, want %v", got, tt.want)
			}
		})
	}
}
