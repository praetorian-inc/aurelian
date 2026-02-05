package recon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	awslink "github.com/praetorian-inc/aurelian/pkg/links/aws"
)

// ============================================================================
// Constructor Tests
// ============================================================================

// TestNewCdkBucketTakeoverV2 tests that the constructor creates a properly initialized instance
func TestNewCdkBucketTakeoverV2(t *testing.T) {
	profile := "test-profile"
	regions := []string{"us-east-1", "us-west-2"}

	detector := NewCdkBucketTakeoverV2(profile, regions)

	require.NotNil(t, detector)
	assert.Equal(t, profile, detector.Profile)
	assert.Equal(t, regions, detector.Regions)
	assert.Equal(t, []string{"hnb659fds"}, detector.Qualifiers, "Qualifiers should default to hnb659fds")
}

// TestWithQualifiers tests the builder method for setting custom qualifiers
func TestWithQualifiers(t *testing.T) {
	detector := NewCdkBucketTakeoverV2("test-profile", []string{"us-east-1"})

	customQualifiers := []string{"custom1", "custom2"}
	result := detector.WithQualifiers(customQualifiers)

	assert.Equal(t, customQualifiers, result.Qualifiers)
	assert.Same(t, detector, result, "WithQualifiers should return the same instance for chaining")
}

// ============================================================================
// Pure Function Tests - extractQualifierFromParameterName
// ============================================================================

func TestExtractQualifierFromParameterName(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "valid default qualifier",
			input:    "/cdk-bootstrap/hnb659fds/version",
			expected: "hnb659fds",
		},
		{
			name:     "valid custom qualifier",
			input:    "/cdk-bootstrap/myqualifier/version",
			expected: "myqualifier",
		},
		{
			name:     "qualifier with numbers",
			input:    "/cdk-bootstrap/qual123/version",
			expected: "qual123",
		},
		{
			name:     "parameter with different suffix",
			input:    "/cdk-bootstrap/hnb659fds/other-param",
			expected: "hnb659fds",
		},
		{
			name:     "invalid prefix",
			input:    "/other/path/version",
			expected: "",
		},
		{
			name:     "empty parameter name",
			input:    "",
			expected: "",
		},
		{
			name:     "just prefix no qualifier",
			input:    "/cdk-bootstrap/",
			expected: "",
		},
		{
			name:     "prefix with trailing slash only",
			input:    "/cdk-bootstrap//version",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractQualifierFromParameterName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// Pure Function Tests - Error Classification
// ============================================================================

func TestIsAccessDeniedError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "AccessDenied error",
			err:      &fakeError{msg: "AccessDenied: User is not authorized"},
			expected: true,
		},
		{
			name:     "access denied lowercase",
			err:      &fakeError{msg: "access denied to this resource"},
			expected: true,
		},
		{
			name:     "not authorized",
			err:      &fakeError{msg: "User is not authorized"},
			expected: true,
		},
		{
			name:     "other error",
			err:      &fakeError{msg: "InternalError: Something went wrong"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAccessDeniedError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsParameterNotFoundError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "ParameterNotFound error",
			err:      &fakeError{msg: "ParameterNotFound: /cdk-bootstrap/version"},
			expected: true,
		},
		{
			name:     "parameter not found lowercase",
			err:      &fakeError{msg: "parameter not found in SSM"},
			expected: true,
		},
		{
			name:     "other error",
			err:      &fakeError{msg: "ThrottlingException: Rate exceeded"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isParameterNotFoundError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// Pure Function Tests - Policy Analysis Helpers
// ============================================================================

func TestStatementAffectsS3(t *testing.T) {
	tests := []struct {
		name      string
		statement map[string]any
		expected  bool
	}{
		{
			name: "single S3 action",
			statement: map[string]any{
				"Action": "s3:GetObject",
			},
			expected: true,
		},
		{
			name: "multiple S3 actions",
			statement: map[string]any{
				"Action": []any{"s3:GetObject", "s3:PutObject"},
			},
			expected: true,
		},
		{
			name: "mixed S3 and other actions",
			statement: map[string]any{
				"Action": []any{"s3:GetObject", "ec2:DescribeInstances"},
			},
			expected: true,
		},
		{
			name: "S3 uppercase action",
			statement: map[string]any{
				"Action": "S3:GetObject",
			},
			expected: true,
		},
		{
			name: "non-S3 action",
			statement: map[string]any{
				"Action": "ec2:DescribeInstances",
			},
			expected: false,
		},
		{
			name: "multiple non-S3 actions",
			statement: map[string]any{
				"Action": []any{"ec2:DescribeInstances", "iam:GetRole"},
			},
			expected: false,
		},
		{
			name: "no action field",
			statement: map[string]any{
				"Effect": "Allow",
			},
			expected: false,
		},
		{
			name:      "empty statement",
			statement: map[string]any{},
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := statementAffectsS3(tt.statement)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHasResourceAccountCondition(t *testing.T) {
	tests := []struct {
		name      string
		statement map[string]any
		accountID string
		expected  bool
	}{
		{
			name: "StringEquals with matching account",
			statement: map[string]any{
				"Condition": map[string]any{
					"StringEquals": map[string]any{
						"aws:ResourceAccount": "123456789012",
					},
				},
			},
			accountID: "123456789012",
			expected:  true,
		},
		{
			name: "StringLike with matching account",
			statement: map[string]any{
				"Condition": map[string]any{
					"StringLike": map[string]any{
						"aws:ResourceAccount": "123456789012",
					},
				},
			},
			accountID: "123456789012",
			expected:  true,
		},
		{
			name: "array of accounts with match",
			statement: map[string]any{
				"Condition": map[string]any{
					"StringEquals": map[string]any{
						"aws:ResourceAccount": []any{"111111111111", "123456789012"},
					},
				},
			},
			accountID: "123456789012",
			expected:  true,
		},
		{
			name: "StringEquals with non-matching account",
			statement: map[string]any{
				"Condition": map[string]any{
					"StringEquals": map[string]any{
						"aws:ResourceAccount": "999999999999",
					},
				},
			},
			accountID: "123456789012",
			expected:  false,
		},
		{
			name: "array without matching account",
			statement: map[string]any{
				"Condition": map[string]any{
					"StringEquals": map[string]any{
						"aws:ResourceAccount": []any{"111111111111", "222222222222"},
					},
				},
			},
			accountID: "123456789012",
			expected:  false,
		},
		{
			name: "no aws:ResourceAccount condition",
			statement: map[string]any{
				"Condition": map[string]any{
					"StringEquals": map[string]any{
						"aws:PrincipalOrgID": "o-123456",
					},
				},
			},
			accountID: "123456789012",
			expected:  false,
		},
		{
			name: "no Condition field",
			statement: map[string]any{
				"Action": "s3:GetObject",
			},
			accountID: "123456789012",
			expected:  false,
		},
		{
			name:      "empty statement",
			statement: map[string]any{},
			accountID: "123456789012",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasResourceAccountCondition(tt.statement, tt.accountID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHasAccountRestrictedResources(t *testing.T) {
	tests := []struct {
		name      string
		statement map[string]any
		accountID string
		expected  bool
	}{
		{
			name: "S3 ARN with account ID",
			statement: map[string]any{
				"Resource": "arn:aws:s3:::cdk-hnb659fds-assets-123456789012-us-east-1/*",
			},
			accountID: "123456789012",
			expected:  true,
		},
		{
			name: "array with S3 ARN containing account",
			statement: map[string]any{
				"Resource": []any{
					"arn:aws:s3:::cdk-hnb659fds-assets-123456789012-us-east-1",
					"arn:aws:s3:::cdk-hnb659fds-assets-123456789012-us-east-1/*",
				},
			},
			accountID: "123456789012",
			expected:  true,
		},
		{
			name: "S3 ARN without account ID",
			statement: map[string]any{
				"Resource": "arn:aws:s3:::public-bucket/*",
			},
			accountID: "123456789012",
			expected:  false,
		},
		{
			name: "wildcard S3 resource",
			statement: map[string]any{
				"Resource": "arn:aws:s3:::*",
			},
			accountID: "123456789012",
			expected:  false,
		},
		{
			name: "non-S3 resource",
			statement: map[string]any{
				"Resource": "arn:aws:iam::123456789012:role/MyRole",
			},
			accountID: "123456789012",
			expected:  false,
		},
		{
			name: "no Resource field",
			statement: map[string]any{
				"Action": "s3:GetObject",
			},
			accountID: "123456789012",
			expected:  false,
		},
		{
			name:      "empty statement",
			statement: map[string]any{},
			accountID: "123456789012",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasAccountRestrictedResources(tt.statement, tt.accountID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ============================================================================
// Risk Generation Tests
// ============================================================================

func TestGenerateBootstrapVersionRisk(t *testing.T) {
	detector := &CdkBucketTakeoverV2{
		accountID: "123456789012",
	}

	role := createTestRole()

	tests := []struct {
		name           string
		bootstrap      awslink.CDKBootstrapInfo
		expectedRisk   bool
		expectedName   string
		expectedStatus string
	}{
		{
			name: "access denied - no risk",
			bootstrap: awslink.CDKBootstrapInfo{
				AccountID:    "123456789012",
				Region:       "us-east-1",
				Qualifier:    "hnb659fds",
				HasVersion:   false,
				Version:      0,
				AccessDenied: true,
			},
			expectedRisk: false,
		},
		{
			name: "version 21 or higher - no risk",
			bootstrap: awslink.CDKBootstrapInfo{
				AccountID:  "123456789012",
				Region:     "us-east-1",
				Qualifier:  "hnb659fds",
				HasVersion: true,
				Version:    21,
			},
			expectedRisk: false,
		},
		{
			name: "version 22 - no risk",
			bootstrap: awslink.CDKBootstrapInfo{
				AccountID:  "123456789012",
				Region:     "us-east-1",
				Qualifier:  "hnb659fds",
				HasVersion: true,
				Version:    22,
			},
			expectedRisk: false,
		},
		{
			name: "version 20 - high risk",
			bootstrap: awslink.CDKBootstrapInfo{
				AccountID:  "123456789012",
				Region:     "us-east-1",
				Qualifier:  "hnb659fds",
				HasVersion: true,
				Version:    20,
			},
			expectedRisk:   true,
			expectedName:   "cdk-bootstrap-outdated",
			expectedStatus: "TH",
		},
		{
			name: "version 10 - high risk",
			bootstrap: awslink.CDKBootstrapInfo{
				AccountID:  "123456789012",
				Region:     "us-east-1",
				Qualifier:  "hnb659fds",
				HasVersion: true,
				Version:    10,
			},
			expectedRisk:   true,
			expectedName:   "cdk-bootstrap-outdated",
			expectedStatus: "TH",
		},
		{
			name: "version missing - medium risk",
			bootstrap: awslink.CDKBootstrapInfo{
				AccountID:  "123456789012",
				Region:     "us-east-1",
				Qualifier:  "hnb659fds",
				HasVersion: false,
				Version:    0,
			},
			expectedRisk:   true,
			expectedName:   "cdk-bootstrap-missing",
			expectedStatus: "TM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risk := detector.generateBootstrapVersionRisk(role, tt.bootstrap)

			if tt.expectedRisk {
				require.NotNil(t, risk, "Expected risk to be generated")
				assert.Equal(t, tt.expectedName, risk.Name)
				assert.Equal(t, tt.expectedStatus, risk.Status)
				assert.Contains(t, risk.Description, role.Region)
				assert.Contains(t, risk.Recommendation, "cdk bootstrap")
			} else {
				assert.Nil(t, risk, "Expected no risk to be generated")
			}
		})
	}
}

func TestGenerateBucketRisk(t *testing.T) {
	detector := &CdkBucketTakeoverV2{
		accountID: "123456789012",
	}

	role := createTestRole()

	tests := []struct {
		name               string
		bucketExists       bool
		bucketOwnedByAcct  bool
		expectedRisk       bool
		expectedName       string
		expectedStatus     string
	}{
		{
			name:               "bucket missing - high risk takeover",
			bucketExists:       false,
			bucketOwnedByAcct:  false,
			expectedRisk:       true,
			expectedName:       "cdk-bucket-takeover",
			expectedStatus:     "TH",
		},
		{
			name:               "bucket exists, owned by different account - medium risk hijacked",
			bucketExists:       true,
			bucketOwnedByAcct:  false,
			expectedRisk:       true,
			expectedName:       "cdk-bucket-hijacked",
			expectedStatus:     "TM",
		},
		{
			name:               "bucket exists, owned by account - no risk",
			bucketExists:       true,
			bucketOwnedByAcct:  true,
			expectedRisk:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risk := detector.generateBucketRisk(role, tt.bucketExists, tt.bucketOwnedByAcct)

			if tt.expectedRisk {
				require.NotNil(t, risk, "Expected risk to be generated")
				assert.Equal(t, tt.expectedName, risk.Name)
				assert.Equal(t, tt.expectedStatus, risk.Status)
				assert.Contains(t, risk.Description, role.BucketName)
				assert.Contains(t, risk.Comment, role.RoleName)
			} else {
				assert.Nil(t, risk, "Expected no risk to be generated")
			}
		})
	}
}

func TestGeneratePolicyRisk(t *testing.T) {
	detector := &CdkBucketTakeoverV2{
		accountID: "123456789012",
	}

	role := createTestRole()

	risk := detector.generatePolicyRisk(role)

	require.NotNil(t, risk)
	assert.Equal(t, "cdk-policy-unrestricted", risk.Name)
	assert.Equal(t, "TM", risk.Status)
	assert.Contains(t, risk.Description, "lacks proper account restrictions")
	assert.Contains(t, risk.Description, role.RoleName)
	assert.Contains(t, risk.Impact, "attacker-controlled S3 buckets")
	assert.Contains(t, risk.Recommendation, "cdk bootstrap")
	assert.Contains(t, risk.Comment, role.RoleName)
	assert.Contains(t, risk.Comment, role.BucketName)
}

// ============================================================================
// Helper Test Data Structures
// ============================================================================

// Helper function to create test role data
func createTestRole() awslink.CDKRoleInfo {
	return awslink.CDKRoleInfo{
		RoleName:   "cdk-hnb659fds-file-publishing-role-123456789012-us-east-1",
		RoleArn:    "arn:aws:iam::123456789012:role/cdk-hnb659fds-file-publishing-role-123456789012-us-east-1",
		Qualifier:  "hnb659fds",
		Region:     "us-east-1",
		AccountID:  "123456789012",
		RoleType:   "file-publishing-role",
		BucketName: "cdk-hnb659fds-assets-123456789012-us-east-1",
	}
}
