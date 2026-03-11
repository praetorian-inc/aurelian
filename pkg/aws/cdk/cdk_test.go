package cdk

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
)

func TestExtractQualifierFromParameterName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"standard version param", "/cdk-bootstrap/hnb659fds/version", "hnb659fds"},
		{"custom qualifier", "/cdk-bootstrap/myqualifier/version", "myqualifier"},
		{"nested path", "/cdk-bootstrap/abc123/some/nested/path", "abc123"},
		{"wrong prefix", "/other/hnb659fds/version", ""},
		{"empty qualifier", "/cdk-bootstrap//version", ""},
		{"just prefix", "/cdk-bootstrap/", ""},
		{"empty string", "", ""},
		{"only prefix no trailing slash content", "/cdk-bootstrap/qualifier", "qualifier"},
		{"prefix with special characters in qualifier", "/cdk-bootstrap/my-qual-123/version", "my-qual-123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractQualifierFromParameterName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCheckPolicyForAccountRestriction(t *testing.T) {
	accountID := "123456789012"

	tests := []struct {
		name     string
		policy   string
		expected bool
	}{
		{
			"has StringEquals aws:ResourceAccount",
			`{"Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":"*","Condition":{"StringEquals":{"aws:ResourceAccount":"123456789012"}}}]}`,
			true,
		},
		{
			"has StringLike aws:ResourceAccount",
			`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","Condition":{"StringLike":{"aws:ResourceAccount":"123456789012"}}}]}`,
			true,
		},
		{
			"aws:ResourceAccount as array",
			`{"Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":"*","Condition":{"StringEquals":{"aws:ResourceAccount":["123456789012","987654321098"]}}}]}`,
			true,
		},
		{
			"wrong account ID",
			`{"Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":"*","Condition":{"StringEquals":{"aws:ResourceAccount":"999999999999"}}}]}`,
			false,
		},
		{
			"no condition",
			`{"Statement":[{"Effect":"Allow","Action":["s3:PutObject"],"Resource":"*"}]}`,
			false,
		},
		{
			"non-S3 action with condition",
			`{"Statement":[{"Effect":"Allow","Action":["ec2:DescribeInstances"],"Resource":"*","Condition":{"StringEquals":{"aws:ResourceAccount":"123456789012"}}}]}`,
			false,
		},
		{
			"URL-encoded policy",
			`%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%5B%22s3%3APutObject%22%5D%2C%22Resource%22%3A%22%2A%22%2C%22Condition%22%3A%7B%22StringEquals%22%3A%7B%22aws%3AResourceAccount%22%3A%22123456789012%22%7D%7D%7D%5D%7D`,
			true,
		},
		{
			"invalid JSON",
			`not a json`,
			false,
		},
		{
			"empty policy",
			`{}`,
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkPolicyForAccountRestriction(tt.policy, accountID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestStatementAffectsS3(t *testing.T) {
	tests := []struct {
		name     string
		stmt     *types.PolicyStatement
		expected bool
	}{
		{
			"s3 action string",
			&types.PolicyStatement{Action: types.NewDynaString([]string{"s3:PutObject"})},
			true,
		},
		{
			"s3 action in array",
			&types.PolicyStatement{Action: types.NewDynaString([]string{"s3:GetObject", "s3:PutObject"})},
			true,
		},
		{
			"mixed actions with s3",
			&types.PolicyStatement{Action: types.NewDynaString([]string{"ec2:DescribeInstances", "s3:ListBucket"})},
			true,
		},
		{
			"no s3 actions",
			&types.PolicyStatement{Action: types.NewDynaString([]string{"ec2:DescribeInstances", "iam:ListRoles"})},
			false,
		},
		{
			"no action key",
			&types.PolicyStatement{Effect: "Allow"},
			false,
		},
		{
			"uppercase S3",
			&types.PolicyStatement{Action: types.NewDynaString([]string{"S3:PutObject"})},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, statementAffectsS3(tt.stmt))
		})
	}
}

func TestHasResourceAccountCondition(t *testing.T) {
	accountID := "123456789012"

	cond := func(operator, key string, values ...string) *types.Condition {
		return &types.Condition{
			operator: types.ConditionStatement{
				key: types.DynaString(values),
			},
		}
	}

	tests := []struct {
		name     string
		stmt     *types.PolicyStatement
		expected bool
	}{
		{
			"StringEquals match",
			&types.PolicyStatement{Condition: cond("StringEquals", "aws:ResourceAccount", "123456789012")},
			true,
		},
		{
			"StringEquals array match",
			&types.PolicyStatement{Condition: cond("StringEquals", "aws:ResourceAccount", "123456789012", "other")},
			true,
		},
		{
			"StringLike match",
			&types.PolicyStatement{Condition: cond("StringLike", "aws:ResourceAccount", "123456789012")},
			true,
		},
		{
			"StringEqualsIgnoreCase match",
			&types.PolicyStatement{Condition: cond("StringEqualsIgnoreCase", "aws:ResourceAccount", "123456789012")},
			true,
		},
		{
			"ForAnyValue:StringEquals match",
			&types.PolicyStatement{Condition: cond("ForAnyValue:StringEquals", "aws:ResourceAccount", "123456789012")},
			true,
		},
		{
			"no condition",
			&types.PolicyStatement{},
			false,
		},
		{
			"wrong account",
			&types.PolicyStatement{Condition: cond("StringEquals", "aws:ResourceAccount", "999999999999")},
			false,
		},
		{
			"unrelated condition key",
			&types.PolicyStatement{Condition: cond("StringEquals", "aws:SourceAccount", "123456789012")},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, hasResourceAccountCondition(tt.stmt, accountID))
		})
	}
}

func TestGenerateBootstrapRisk(t *testing.T) {
	role := RoleInfo{
		RoleName:   "cdk-hnb659fds-cfn-exec-role-123456789012-us-east-1",
		Qualifier:  "hnb659fds",
		Region:     "us-east-1",
		AccountID:  "123456789012",
		BucketName: "cdk-hnb659fds-assets-123456789012-us-east-1",
	}

	t.Run("access denied returns nil", func(t *testing.T) {
		info := BootstrapInfo{AccessDenied: true}
		assert.Nil(t, generateBootstrapRisk(role, info))
	})

	t.Run("version >= 21 returns nil", func(t *testing.T) {
		info := BootstrapInfo{HasVersion: true, Version: 21}
		assert.Nil(t, generateBootstrapRisk(role, info))
	})

	t.Run("version well above 21 returns nil", func(t *testing.T) {
		info := BootstrapInfo{HasVersion: true, Version: 50}
		assert.Nil(t, generateBootstrapRisk(role, info))
	})

	t.Run("version < 21 returns high risk", func(t *testing.T) {
		info := BootstrapInfo{HasVersion: true, Version: 14, Region: "us-east-1", Qualifier: "hnb659fds"}
		risk := generateBootstrapRisk(role, info)
		assert.NotNil(t, risk)
		assert.Equal(t, "cdk-bootstrap-outdated", risk.Name)
		assert.Equal(t, "TH", risk.Status)
		assert.Equal(t, "aurelian-cdk-scanner", risk.Source)
		assert.Equal(t, "123456789012", risk.DNS)
		assert.Contains(t, risk.Description, "14")
		assert.Contains(t, risk.Description, "us-east-1")
		assert.NotNil(t, risk.Target)
		assert.Equal(t, "AWS::IAM::Root", risk.Target.ResourceType)
		assert.Equal(t, "arn:aws:iam::123456789012:root", risk.Target.ResourceID)
	})

	t.Run("version == 20 returns high risk", func(t *testing.T) {
		info := BootstrapInfo{HasVersion: true, Version: 20, Region: "us-east-1", Qualifier: "hnb659fds"}
		risk := generateBootstrapRisk(role, info)
		assert.NotNil(t, risk)
		assert.Equal(t, "cdk-bootstrap-outdated", risk.Name)
		assert.Equal(t, "TH", risk.Status)
	})

	t.Run("missing version returns medium risk", func(t *testing.T) {
		info := BootstrapInfo{HasVersion: false, Region: "us-east-1", Qualifier: "hnb659fds"}
		risk := generateBootstrapRisk(role, info)
		assert.NotNil(t, risk)
		assert.Equal(t, "cdk-bootstrap-missing", risk.Name)
		assert.Equal(t, "TM", risk.Status)
		assert.Equal(t, "aurelian-cdk-scanner", risk.Source)
		assert.Contains(t, risk.Description, "not found")
		assert.Contains(t, risk.Comment, "Missing")
	})
}

func TestGenerateBucketTakeoverRisk(t *testing.T) {
	role := RoleInfo{
		RoleName:   "cdk-hnb659fds-file-publishing-role-123456789012-us-east-1",
		BucketName: "cdk-hnb659fds-assets-123456789012-us-east-1",
		Qualifier:  "hnb659fds",
		Region:     "us-east-1",
		AccountID:  "123456789012",
	}

	risk := generateBucketTakeoverRisk(role)
	assert.NotNil(t, risk)
	assert.Equal(t, "cdk-bucket-takeover", risk.Name)
	assert.Equal(t, "TH", risk.Status)
	assert.Equal(t, "aurelian-cdk-scanner", risk.Source)
	assert.Equal(t, "123456789012", risk.DNS)
	assert.Contains(t, risk.Description, role.BucketName)
	assert.Contains(t, risk.Description, role.RoleName)
	assert.Contains(t, risk.Description, "us-east-1")
	assert.NotNil(t, risk.Target)
	assert.Equal(t, "arn:aws:iam::123456789012:root", risk.Target.ResourceID)
	assert.Equal(t, role.BucketName, risk.Target.Properties["BucketName"])
	assert.Equal(t, role.RoleName, risk.Target.Properties["RoleName"])
}

func TestGenerateBucketHijackedRisk(t *testing.T) {
	role := RoleInfo{
		RoleName:   "cdk-hnb659fds-file-publishing-role-123456789012-us-east-1",
		BucketName: "cdk-hnb659fds-assets-123456789012-us-east-1",
		Qualifier:  "hnb659fds",
		Region:     "us-east-1",
		AccountID:  "123456789012",
	}

	risk := generateBucketHijackedRisk(role)
	assert.NotNil(t, risk)
	assert.Equal(t, "cdk-bucket-hijacked", risk.Name)
	assert.Equal(t, "TM", risk.Status)
	assert.Equal(t, "aurelian-cdk-scanner", risk.Source)
	assert.Contains(t, risk.Description, role.BucketName)
	assert.Contains(t, risk.Description, role.RoleName)
	assert.Contains(t, risk.Description, "different account")
}

func TestGeneratePolicyRisk(t *testing.T) {
	role := RoleInfo{
		RoleName:   "cdk-hnb659fds-file-publishing-role-123456789012-us-east-1",
		BucketName: "cdk-hnb659fds-assets-123456789012-us-east-1",
		Qualifier:  "hnb659fds",
		Region:     "us-east-1",
		AccountID:  "123456789012",
	}

	risk := generatePolicyRisk(role)
	assert.NotNil(t, risk)
	assert.Equal(t, "cdk-policy-unrestricted", risk.Name)
	assert.Equal(t, "TM", risk.Status)
	assert.Equal(t, "aurelian-cdk-scanner", risk.Source)
	assert.Contains(t, risk.Description, "FilePublishingRole")
	assert.Contains(t, risk.Description, role.RoleName)
	assert.Contains(t, risk.Recommendation, "us-east-1")
	assert.Contains(t, risk.Recommendation, "cdk bootstrap")
	assert.Equal(t, role.BucketName, risk.Target.Properties["BucketName"])
}

func TestCdkRoleTypes(t *testing.T) {
	assert.Len(t, cdkRoleTypes, 5)

	expected := []string{
		"file-publishing-role",
		"cfn-exec-role",
		"image-publishing-role",
		"lookup-role",
		"deploy-role",
	}

	for _, roleType := range expected {
		assert.Contains(t, cdkRoleTypes, roleType, "expected %q in cdkRoleTypes", roleType)
	}
}

func TestCheckPolicyForAccountRestrictionMultipleStatements(t *testing.T) {
	accountID := "123456789012"

	t.Run("second statement has restriction", func(t *testing.T) {
		policy := `{
			"Statement": [
				{"Effect": "Allow", "Action": "ec2:DescribeInstances", "Resource": "*"},
				{"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*", "Condition": {"StringEquals": {"aws:ResourceAccount": "123456789012"}}}
			]
		}`
		assert.True(t, checkPolicyForAccountRestriction(policy, accountID))
	})

	t.Run("s3 statement without restriction among others", func(t *testing.T) {
		policy := `{
			"Statement": [
				{"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*"},
				{"Effect": "Allow", "Action": "ec2:DescribeInstances", "Resource": "*"}
			]
		}`
		assert.False(t, checkPolicyForAccountRestriction(policy, accountID))
	})
}
