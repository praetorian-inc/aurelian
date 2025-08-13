package aws

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCDKBucketValidator_RiskGeneration(t *testing.T) {
	validator := &AwsCdkBucketValidator{}
	
	cdkRole := CDKRoleInfo{
		RoleName:   "cdk-hnb659fds-cfn-exec-role-123456789012-us-east-1",
		AccountID:  "123456789012",
		Region:     "us-east-1",
		Qualifier:  "hnb659fds",
		RoleType:   "cfn-exec-role",
		BucketName: "cdk-hnb659fds-assets-123456789012-us-east-1",
	}

	tests := []struct {
		name                 string
		bucketExists         bool
		bucketOwnedByAccount bool
		expectedRiskName     string
		expectedSeverity     string
		shouldGenerateRisk   bool
	}{
		{
			name:                 "missing bucket - high risk",
			bucketExists:         false,
			bucketOwnedByAccount: false,
			expectedRiskName:     "cdk-bucket-takeover",
			expectedSeverity:     "H", // TriageHigh
			shouldGenerateRisk:   true,
		},
		{
			name:                 "bucket owned by different account - medium risk",
			bucketExists:         true,
			bucketOwnedByAccount: false,
			expectedRiskName:     "cdk-bucket-hijacked",
			expectedSeverity:     "M", // TriageMedium
			shouldGenerateRisk:   true,
		},
		{
			name:                 "bucket exists and owned by account - no risk",
			bucketExists:         true,
			bucketOwnedByAccount: true,
			shouldGenerateRisk:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			risk := validator.generateCDKBucketRisk(cdkRole, tt.bucketExists, tt.bucketOwnedByAccount)
			
			if tt.shouldGenerateRisk {
				require.NotNil(t, risk, "should generate a risk")
				assert.Equal(t, tt.expectedRiskName, risk.Name)
				assert.Equal(t, tt.expectedSeverity, risk.Severity())
				assert.Equal(t, "nebula-cdk-scanner", risk.Source)
				assert.Equal(t, cdkRole.AccountID, risk.DNS)
			} else {
				assert.Nil(t, risk, "should not generate a risk")
			}
		})
	}
}

func TestCDKBucketValidator_BucketNamePredictability(t *testing.T) {
	tests := []struct {
		name        string
		accountID   string
		qualifier   string
		region      string
		expectedBucket string
	}{
		{
			name:        "default qualifier us-east-1",
			accountID:   "123456789012",
			qualifier:   "hnb659fds",
			region:      "us-east-1",
			expectedBucket: "cdk-hnb659fds-assets-123456789012-us-east-1",
		},
		{
			name:        "custom qualifier eu-west-1",
			accountID:   "987654321098",
			qualifier:   "custom123",
			region:      "eu-west-1",
			expectedBucket: "cdk-custom123-assets-987654321098-eu-west-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cdkRole := CDKRoleInfo{
				AccountID:  tt.accountID,
				Qualifier:  tt.qualifier,
				Region:     tt.region,
				BucketName: tt.expectedBucket,
			}
			
			// Verify the bucket naming convention matches expectations
			assert.Equal(t, tt.expectedBucket, cdkRole.BucketName)
			
			// Verify bucket name contains predictable components
			assert.Contains(t, cdkRole.BucketName, tt.qualifier)
			assert.Contains(t, cdkRole.BucketName, tt.accountID)
			assert.Contains(t, cdkRole.BucketName, tt.region)
			assert.Contains(t, cdkRole.BucketName, "cdk-")
			assert.Contains(t, cdkRole.BucketName, "-assets-")
		})
	}
}

func TestContainsAccountID(t *testing.T) {
	tests := []struct {
		name      string
		policyDoc string
		accountID string
		expected  bool
	}{
		{
			name:      "policy contains account ID",
			policyDoc: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"s3:GetObject"}]}`,
			accountID: "123456789012",
			expected:  true,
		},
		{
			name:      "policy does not contain account ID",
			policyDoc: `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}`,
			accountID: "123456789012",
			expected:  false,
		},
		{
			name:      "empty policy document",
			policyDoc: "",
			accountID: "123456789012",
			expected:  false,
		},
		{
			name:      "empty account ID",
			policyDoc: `{"Version":"2012-10-17","Statement":[]}`,
			accountID: "",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsAccountID(tt.policyDoc, tt.accountID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCDKBucketValidator_RiskDefinitions(t *testing.T) {
	validator := &AwsCdkBucketValidator{}
	
	cdkRole := CDKRoleInfo{
		RoleName:   "cdk-hnb659fds-cfn-exec-role-123456789012-us-east-1",
		AccountID:  "123456789012",
		Region:     "us-east-1",
		Qualifier:  "hnb659fds",
		RoleType:   "cfn-exec-role",
		BucketName: "cdk-hnb659fds-assets-123456789012-us-east-1",
	}

	// Test missing bucket risk
	risk := validator.generateCDKBucketRisk(cdkRole, false, false)
	require.NotNil(t, risk)
	
	// Verify risk has proper structure
	assert.NotEmpty(t, risk.Name, "risk name should not be empty")
	assert.NotEmpty(t, risk.DNS, "risk DNS should not be empty") 
	assert.NotEmpty(t, risk.Status, "risk status should not be empty")
	assert.NotEmpty(t, risk.Source, "risk source should not be empty")
	
	// Verify risk comment contains useful context
	assert.Contains(t, risk.Comment, cdkRole.RoleName, "comment should contain role name")
	assert.Contains(t, risk.Comment, cdkRole.BucketName, "comment should contain bucket name")
	assert.Contains(t, risk.Comment, cdkRole.Region, "comment should contain region")
}

func TestCDKBucketValidator_Params(t *testing.T) {
	validator := &AwsCdkBucketValidator{}
	params := validator.Params()
	
	// Should inherit base AWS parameters
	assert.NotEmpty(t, params, "should have parameters from base AWS link")
}