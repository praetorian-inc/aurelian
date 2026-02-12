package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPolicyFromJSON(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		expectError bool
		errContains string
		policy      *Policy
	}{
		{
			name: "valid policy with single action and resource",
			input: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::example-bucket/*"
					}
				]
			}`,
			expectError: false,
			policy: &Policy{
				Version: "2012-10-17",
				Statement: &PolicyStatementList{
					{
						Effect:   "Allow",
						Action:   NewDynaString([]string{"s3:GetObject"}),
						Resource: NewDynaString([]string{"arn:aws:s3:::example-bucket/*"}),
					},
				},
			},
		},
		{
			name: "valid policy with action list",
			input: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Allow",
						"Action": ["s3:GetObject", "s3:ListBucket"],
						"Resource": "arn:aws:s3:::example-bucket/*"
					}
				]
			}`,
			expectError: false,
			policy: &Policy{
				Version: "2012-10-17",
				Statement: &PolicyStatementList{
					{
						Effect:   "Allow",
						Action:   NewDynaString([]string{"s3:GetObject", "s3:ListBucket"}),
						Resource: NewDynaString([]string{"arn:aws:s3:::example-bucket/*"}),
					},
				},
			},
		},
		{
			name: "valid policy with Id field",
			input: `{
				"Id": "MyPolicy",
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Deny",
						"Action": "s3:*",
						"Resource": "*"
					}
				]
			}`,
			expectError: false,
			policy: &Policy{
				Id:      "MyPolicy",
				Version: "2012-10-17",
				Statement: &PolicyStatementList{
					{
						Effect:   "Deny",
						Action:   NewDynaString([]string{"s3:*"}),
						Resource: NewDynaString([]string{"*"}),
					},
				},
			},
		},
		{
			name: "missing version returns error",
			input: `{
				"Statement": [
					{
						"Effect": "Allow",
						"Action": "s3:GetObject",
						"Resource": "arn:aws:s3:::example-bucket/*"
					}
				]
			}`,
			expectError: true,
			errContains: "missing version",
		},
		{
			name: "empty statements returns error",
			input: `{
				"Version": "2012-10-17",
				"Statement": []
			}`,
			expectError: true,
			errContains: "empty statements",
		},
		{
			name:        "invalid JSON returns error",
			input:       `{"Version": "2012-10-17", "Statement": [{"Effect": "Allow"`,
			expectError: true,
		},
		{
			name: "single statement object (not array) parses correctly",
			input: `{
				"Version": "2012-10-17",
				"Statement": {
					"Effect": "Allow",
					"Action": "sts:AssumeRole",
					"Resource": "*"
				}
			}`,
			expectError: false,
			policy: &Policy{
				Version: "2012-10-17",
				Statement: &PolicyStatementList{
					{
						Effect:   "Allow",
						Action:   NewDynaString([]string{"sts:AssumeRole"}),
						Resource: NewDynaString([]string{"*"}),
					},
				},
			},
		},
		{
			name: "policy with NotAction and NotResource",
			input: `{
				"Version": "2012-10-17",
				"Statement": [
					{
						"Effect": "Deny",
						"NotAction": "iam:*",
						"NotResource": "arn:aws:iam::*:role/admin"
					}
				]
			}`,
			expectError: false,
			policy: &Policy{
				Version: "2012-10-17",
				Statement: &PolicyStatementList{
					{
						Effect:      "Deny",
						NotAction:   NewDynaString([]string{"iam:*"}),
						NotResource: NewDynaString([]string{"arn:aws:iam::*:role/admin"}),
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := NewPolicyFromJSON([]byte(tc.input))
			if tc.expectError {
				require.Error(t, err)
				if tc.errContains != "" {
					assert.Contains(t, err.Error(), tc.errContains)
				}
				assert.Nil(t, policy)
			} else {
				require.NoError(t, err)
				require.NotNil(t, policy)
				if tc.policy != nil {
					assert.Equal(t, tc.policy.Version, policy.Version)
					assert.Equal(t, tc.policy.Id, policy.Id)
					require.NotNil(t, policy.Statement)
					assert.Equal(t, len(*tc.policy.Statement), len(*policy.Statement))
					for i, expected := range *tc.policy.Statement {
						actual := (*policy.Statement)[i]
						assert.Equal(t, expected.Effect, actual.Effect)
						assert.Equal(t, expected.Action, actual.Action)
						assert.Equal(t, expected.NotAction, actual.NotAction)
						assert.Equal(t, expected.Resource, actual.Resource)
						assert.Equal(t, expected.NotResource, actual.NotResource)
					}
				}
			}
		})
	}
}

func TestPrincipalUnmarshalJSON(t *testing.T) {
	t.Run("wildcard principal expands to all types", func(t *testing.T) {
		policy, err := NewPolicyFromJSON([]byte(`{
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Principal": "*",
				"Action": "s3:GetObject",
				"Resource": "*"
			}]
		}`))
		require.NoError(t, err)
		stmt := (*policy.Statement)[0]
		require.NotNil(t, stmt.Principal)
		assert.Equal(t, DynaString{"*"}, *stmt.Principal.AWS)
		assert.Equal(t, DynaString{"*"}, *stmt.Principal.Service)
		assert.Equal(t, DynaString{"*"}, *stmt.Principal.Federated)
		assert.Equal(t, DynaString{"*"}, *stmt.Principal.CanonicalUser)
	})

	t.Run("AWS principal parses correctly", func(t *testing.T) {
		policy, err := NewPolicyFromJSON([]byte(`{
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
				"Action": "s3:GetObject",
				"Resource": "*"
			}]
		}`))
		require.NoError(t, err)
		stmt := (*policy.Statement)[0]
		require.NotNil(t, stmt.Principal)
		require.NotNil(t, stmt.Principal.AWS)
		assert.Equal(t, DynaString{"arn:aws:iam::123456789012:root"}, *stmt.Principal.AWS)
		assert.Nil(t, stmt.Principal.Service)
	})

	t.Run("service principal parses correctly", func(t *testing.T) {
		policy, err := NewPolicyFromJSON([]byte(`{
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Principal": {"Service": "lambda.amazonaws.com"},
				"Action": "sts:AssumeRole",
				"Resource": "*"
			}]
		}`))
		require.NoError(t, err)
		stmt := (*policy.Statement)[0]
		require.NotNil(t, stmt.Principal)
		require.NotNil(t, stmt.Principal.Service)
		assert.Equal(t, DynaString{"lambda.amazonaws.com"}, *stmt.Principal.Service)
	})

	t.Run("multiple AWS principals parse as list", func(t *testing.T) {
		policy, err := NewPolicyFromJSON([]byte(`{
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Allow",
				"Principal": {"AWS": ["arn:aws:iam::111111111111:root", "arn:aws:iam::222222222222:root"]},
				"Action": "s3:GetObject",
				"Resource": "*"
			}]
		}`))
		require.NoError(t, err)
		stmt := (*policy.Statement)[0]
		require.NotNil(t, stmt.Principal.AWS)
		assert.Len(t, *stmt.Principal.AWS, 2)
		assert.Contains(t, []string(*stmt.Principal.AWS), "arn:aws:iam::111111111111:root")
		assert.Contains(t, []string(*stmt.Principal.AWS), "arn:aws:iam::222222222222:root")
	})
}

func TestExtractPrincipals(t *testing.T) {
	t.Run("nil statement returns empty", func(t *testing.T) {
		var stmt *PolicyStatement
		result := stmt.ExtractPrincipals()
		assert.Empty(t, result)
	})

	t.Run("nil principal returns empty", func(t *testing.T) {
		stmt := &PolicyStatement{}
		result := stmt.ExtractPrincipals()
		assert.Empty(t, result)
	})

	t.Run("extracts AWS principals", func(t *testing.T) {
		aws := DynaString{"arn:aws:iam::123456789012:root"}
		stmt := &PolicyStatement{
			Principal: &Principal{AWS: &aws},
		}
		result := stmt.ExtractPrincipals()
		assert.Equal(t, []string{"arn:aws:iam::123456789012:root"}, result)
	})

	t.Run("extracts service principals", func(t *testing.T) {
		svc := DynaString{"lambda.amazonaws.com"}
		stmt := &PolicyStatement{
			Principal: &Principal{Service: &svc},
		}
		result := stmt.ExtractPrincipals()
		assert.Equal(t, []string{"lambda.amazonaws.com"}, result)
	})

	t.Run("extracts federated principals", func(t *testing.T) {
		fed := DynaString{"accounts.google.com"}
		stmt := &PolicyStatement{
			Principal: &Principal{Federated: &fed},
		}
		result := stmt.ExtractPrincipals()
		assert.Equal(t, []string{"accounts.google.com"}, result)
	})

	t.Run("extracts canonical user principals", func(t *testing.T) {
		cu := DynaString{"abc123canonical"}
		stmt := &PolicyStatement{
			Principal: &Principal{CanonicalUser: &cu},
		}
		result := stmt.ExtractPrincipals()
		assert.Equal(t, []string{"abc123canonical"}, result)
	})

	t.Run("extracts all principal types together", func(t *testing.T) {
		aws := DynaString{"arn:aws:iam::123456789012:root"}
		svc := DynaString{"lambda.amazonaws.com"}
		fed := DynaString{"cognito-identity.amazonaws.com"}
		cu := DynaString{"canonical123"}
		stmt := &PolicyStatement{
			Principal: &Principal{
				AWS:           &aws,
				Service:       &svc,
				Federated:     &fed,
				CanonicalUser: &cu,
			},
		}
		result := stmt.ExtractPrincipals()
		assert.Len(t, result, 4)
		assert.Contains(t, result, "arn:aws:iam::123456789012:root")
		assert.Contains(t, result, "lambda.amazonaws.com")
		assert.Contains(t, result, "cognito-identity.amazonaws.com")
		assert.Contains(t, result, "canonical123")
	})

	t.Run("skips empty strings in principals", func(t *testing.T) {
		aws := DynaString{"arn:aws:iam::123456789012:root", "", "arn:aws:iam::999999999999:root"}
		stmt := &PolicyStatement{
			Principal: &Principal{AWS: &aws},
		}
		result := stmt.ExtractPrincipals()
		assert.Len(t, result, 2)
		assert.NotContains(t, result, "")
	})
}

func TestPrincipalString(t *testing.T) {
	t.Run("nil principal returns nil string", func(t *testing.T) {
		var p *Principal
		assert.Equal(t, "nil", p.String())
	})

	t.Run("AWS principal formats correctly", func(t *testing.T) {
		aws := DynaString{"arn:aws:iam::123456789012:root"}
		p := &Principal{AWS: &aws}
		assert.Equal(t, "AWS: arn:aws:iam::123456789012:root", p.String())
	})

	t.Run("Service principal formats correctly", func(t *testing.T) {
		svc := DynaString{"lambda.amazonaws.com"}
		p := &Principal{Service: &svc}
		assert.Equal(t, "Service: lambda.amazonaws.com", p.String())
	})

	t.Run("Federated principal formats correctly", func(t *testing.T) {
		fed := DynaString{"cognito-identity.amazonaws.com"}
		p := &Principal{Federated: &fed}
		assert.Equal(t, "Federated: cognito-identity.amazonaws.com", p.String())
	})

	t.Run("CanonicalUser principal formats correctly", func(t *testing.T) {
		cu := DynaString{"canonical123"}
		p := &Principal{CanonicalUser: &cu}
		assert.Equal(t, "CanonicalUser: canonical123", p.String())
	})

	t.Run("empty principal returns empty string", func(t *testing.T) {
		p := &Principal{}
		assert.Equal(t, "", p.String())
	})
}

func TestDynaStringUnmarshalJSON(t *testing.T) {
	t.Run("single string parses as single-element slice", func(t *testing.T) {
		policy, err := NewPolicyFromJSON([]byte(`{
			"Version": "2012-10-17",
			"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]
		}`))
		require.NoError(t, err)
		action := (*policy.Statement)[0].Action
		require.NotNil(t, action)
		assert.Equal(t, DynaString{"s3:GetObject"}, *action)
	})

	t.Run("string array parses as multi-element slice", func(t *testing.T) {
		policy, err := NewPolicyFromJSON([]byte(`{
			"Version": "2012-10-17",
			"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject"], "Resource": "*"}]
		}`))
		require.NoError(t, err)
		action := (*policy.Statement)[0].Action
		require.NotNil(t, action)
		assert.Equal(t, DynaString{"s3:GetObject", "s3:PutObject"}, *action)
	})

	t.Run("boolean value parses as string", func(t *testing.T) {
		// Conditions can have boolean values in DynaString
		policy, err := NewPolicyFromJSON([]byte(`{
			"Version": "2012-10-17",
			"Statement": [{
				"Effect": "Deny",
				"Action": "s3:*",
				"Resource": "*",
				"Condition": {
					"Bool": {
						"aws:SecureTransport": false
					}
				}
			}]
		}`))
		require.NoError(t, err)
		stmt := (*policy.Statement)[0]
		require.NotNil(t, stmt.Condition)
		cond := *stmt.Condition
		boolCond, ok := cond["Bool"]
		require.True(t, ok)
		vals, ok := boolCond["aws:SecureTransport"]
		require.True(t, ok)
		assert.Equal(t, DynaString{"false"}, vals)
	})
}

func TestDynaStringToHumanReadable(t *testing.T) {
	t.Run("empty returns 'empty'", func(t *testing.T) {
		d := DynaString{}
		assert.Equal(t, "empty", d.ToHumanReadable())
	})

	t.Run("single value returns value directly", func(t *testing.T) {
		d := DynaString{"s3:GetObject"}
		assert.Equal(t, "s3:GetObject", d.ToHumanReadable())
	})

	t.Run("multiple values returns bracketed list", func(t *testing.T) {
		d := DynaString{"s3:GetObject", "s3:PutObject"}
		assert.Equal(t, "[s3:GetObject, s3:PutObject]", d.ToHumanReadable())
	})
}

func TestNewDynaString(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := NewDynaString(nil)
		assert.Nil(t, result)
	})

	t.Run("non-nil input returns pointer to DynaString", func(t *testing.T) {
		result := NewDynaString([]string{"a", "b"})
		require.NotNil(t, result)
		assert.Equal(t, DynaString{"a", "b"}, *result)
	})

	t.Run("empty slice returns pointer to empty DynaString", func(t *testing.T) {
		result := NewDynaString([]string{})
		require.NotNil(t, result)
		assert.Empty(t, *result)
	})
}

func TestConditionToHumanReadable(t *testing.T) {
	t.Run("simple string equals condition", func(t *testing.T) {
		cond := Condition{
			"StringEquals": ConditionStatement{
				"aws:PrincipalOrgID": DynaString{"o-abc123"},
			},
		}
		result := cond.ToHumanReadable()
		assert.Contains(t, result, "aws:PrincipalOrgID")
		assert.Contains(t, result, "string equals")
		assert.Contains(t, result, "o-abc123")
	})

	t.Run("augmented ForAllValues operator", func(t *testing.T) {
		cond := Condition{
			"ForAllValues:StringEquals": ConditionStatement{
				"aws:TagKeys": DynaString{"env", "team"},
			},
		}
		result := cond.ToHumanReadable()
		assert.Contains(t, result, "for all values")
		assert.Contains(t, result, "string equals")
	})

	t.Run("augmented ForAnyValue operator", func(t *testing.T) {
		cond := Condition{
			"ForAnyValue:StringLike": ConditionStatement{
				"aws:PrincipalTag/department": DynaString{"engineering*"},
			},
		}
		result := cond.ToHumanReadable()
		assert.Contains(t, result, "for any value")
		assert.Contains(t, result, "string matches")
	})

	t.Run("augmented IfExists operator", func(t *testing.T) {
		cond := Condition{
			"StringEqualsIfExists": ConditionStatement{
				"aws:RequestedRegion": DynaString{"us-east-1"},
			},
		}
		result := cond.ToHumanReadable()
		assert.Contains(t, result, "if it exists")
		assert.Contains(t, result, "string equals")
	})
}

func TestConvertOperator(t *testing.T) {
	tests := []struct {
		operator string
		expected string
	}{
		{"StringEquals", "string equals"},
		{"StringNotEquals", "string does not equal"},
		{"StringEqualsIgnoreCase", "string equals (case-insensitive)"},
		{"StringNotEqualsIgnoreCase", "string does not equal (case-insensitive)"},
		{"StringLike", "string matches (incl. * and ?)"},
		{"StringNotLike", "string does not match (incl. * and ?)"},
		{"NumericEquals", "equals number"},
		{"NumericNotEquals", "not equals number"},
		{"NumericLessThan", "less than number"},
		{"NumericLessThanEquals", "less than or equals number"},
		{"NumericGreaterThan", "greater than number"},
		{"NumericGreaterThanEquals", "greater than or equals number"},
		{"Bool", "is boolean"},
		{"IpAddress", "is IP or in IP range"},
		{"NotIpAddress", "is not IP or not in IP range"},
		{"ArnEquals", "is same as ARN"},
		{"ArnLike", "is same as ARN"},
		{"ArnNotEquals", "is not same as ARN"},
		{"ArnNotLike", "is not same as ARN"},
		{"DateEquals", "is date"},
		{"DateNotEquals", "is not date"},
		{"DateLessThan", "happened before date"},
		{"DateLessThanEquals", "happened on or before date"},
		{"DateGreaterThan", "happened after date"},
		{"DateGreaterThanEquals", "happened on or after date"},
		{"Null", "for existence of"},
		{"UnknownOperator", "UnknownOperator"},
	}

	for _, tc := range tests {
		t.Run(tc.operator, func(t *testing.T) {
			assert.Equal(t, tc.expected, convertOperator(tc.operator))
		})
	}
}

func TestPolicyWithConditions(t *testing.T) {
	t.Run("full policy with conditions parses correctly", func(t *testing.T) {
		input := `{
			"Version": "2012-10-17",
			"Statement": [{
				"Sid": "AllowS3FromVPC",
				"Effect": "Allow",
				"Action": ["s3:GetObject", "s3:PutObject"],
				"Resource": "arn:aws:s3:::my-bucket/*",
				"Condition": {
					"StringEquals": {
						"aws:SourceVpc": "vpc-abc123"
					}
				}
			}]
		}`
		policy, err := NewPolicyFromJSON([]byte(input))
		require.NoError(t, err)
		stmt := (*policy.Statement)[0]
		assert.Equal(t, "AllowS3FromVPC", stmt.Sid)
		assert.Equal(t, "Allow", stmt.Effect)
		require.NotNil(t, stmt.Action)
		assert.Len(t, *stmt.Action, 2)
		require.NotNil(t, stmt.Condition)
		cond := *stmt.Condition
		strEq, ok := cond["StringEquals"]
		require.True(t, ok)
		vals, ok := strEq["aws:SourceVpc"]
		require.True(t, ok)
		assert.Equal(t, DynaString{"vpc-abc123"}, vals)
	})
}

func TestPolicyStatementListUnmarshal(t *testing.T) {
	t.Run("invalid statement data returns error", func(t *testing.T) {
		_, err := NewPolicyFromJSON([]byte(`{
			"Version": "2012-10-17",
			"Statement": 12345
		}`))
		require.Error(t, err)
	})
}
