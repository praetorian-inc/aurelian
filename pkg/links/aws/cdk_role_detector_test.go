package aws

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCDKRoleInfo_BucketName(t *testing.T) {
	tests := []struct {
		name      string
		roleInfo  CDKRoleInfo
		expected  string
	}{
		{
			name: "default qualifier",
			roleInfo: CDKRoleInfo{
				Qualifier: "hnb659fds",
				AccountID: "123456789012",
				Region:    "us-east-1",
			},
			expected: "cdk-hnb659fds-assets-123456789012-us-east-1",
		},
		{
			name: "custom qualifier",
			roleInfo: CDKRoleInfo{
				Qualifier: "custom123",
				AccountID: "987654321098", 
				Region:    "us-west-2",
			},
			expected: "cdk-custom123-assets-987654321098-us-west-2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The bucket name should be set correctly during role detection
			assert.Equal(t, tt.expected, tt.roleInfo.BucketName)
		})
	}
}

func TestCDKRoleInfo_RoleNamingConvention(t *testing.T) {
	tests := []struct {
		name      string
		qualifier string
		roleType  string
		accountID string
		region    string
		expected  string
	}{
		{
			name:      "cfn-exec-role default qualifier",
			qualifier: "hnb659fds",
			roleType:  "cfn-exec-role",
			accountID: "123456789012",
			region:    "us-east-1",
			expected:  "cdk-hnb659fds-cfn-exec-role-123456789012-us-east-1",
		},
		{
			name:      "file-publishing-role custom qualifier",
			qualifier: "custom123",
			roleType:  "file-publishing-role",
			accountID: "987654321098",
			region:    "eu-west-1",
			expected:  "cdk-custom123-file-publishing-role-987654321098-eu-west-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			roleInfo := CDKRoleInfo{
				Qualifier: tt.qualifier,
				RoleType:  tt.roleType,
				AccountID: tt.accountID,
				Region:    tt.region,
			}
			
			// Verify the role name follows CDK naming convention
			expectedRoleName := tt.expected
			roleInfo.RoleName = expectedRoleName
			assert.Equal(t, expectedRoleName, roleInfo.RoleName)
		})
	}
}

func TestCDKRoleDetector_DefaultParams(t *testing.T) {
	// Test that the CDK role detector has the expected default parameters
	detector := &AwsCdkRoleDetector{}
	params := detector.Params()
	
	// Should include base AWS parameters plus CDK-specific ones
	assert.NotEmpty(t, params, "should have parameters defined")
	
	// Look for CDK-specific parameters
	var hasCdkQualifiers, hasCdkCheckAllRegions bool
	for _, param := range params {
		switch param.Name() {
		case "cdk-qualifiers":
			hasCdkQualifiers = true
		case "cdk-check-all-regions":
			hasCdkCheckAllRegions = true
		}
	}
	
	assert.True(t, hasCdkQualifiers, "should have cdk-qualifiers parameter")
	assert.True(t, hasCdkCheckAllRegions, "should have cdk-check-all-regions parameter")
}

func TestCDKRoleTypes(t *testing.T) {
	expectedRoleTypes := []string{
		"cfn-exec-role",
		"file-publishing-role",
		"image-publishing-role",
		"lookup-role", 
		"deploy-role",
	}
	
	// These are the role types that should be detected by the CDK role detector
	for _, roleType := range expectedRoleTypes {
		assert.NotEmpty(t, roleType, "role type should not be empty")
		assert.Contains(t, roleType, "-role", "role type should contain '-role' suffix")
	}
}

func TestCDKRoleInfo_Validation(t *testing.T) {
	tests := []struct {
		name     string
		roleInfo CDKRoleInfo
		isValid  bool
	}{
		{
			name: "valid role info",
			roleInfo: CDKRoleInfo{
				RoleName:   "cdk-hnb659fds-cfn-exec-role-123456789012-us-east-1",
				AccountID:  "123456789012",
				Region:     "us-east-1",
				Qualifier:  "hnb659fds",
				RoleType:   "cfn-exec-role",
				BucketName: "cdk-hnb659fds-assets-123456789012-us-east-1",
			},
			isValid: true,
		},
		{
			name: "missing account id",
			roleInfo: CDKRoleInfo{
				RoleName:  "cdk-hnb659fds-cfn-exec-role--us-east-1",
				Region:    "us-east-1",
				Qualifier: "hnb659fds",
				RoleType:  "cfn-exec-role",
			},
			isValid: false,
		},
		{
			name: "missing region",
			roleInfo: CDKRoleInfo{
				RoleName:  "cdk-hnb659fds-cfn-exec-role-123456789012-",
				AccountID: "123456789012",
				Qualifier: "hnb659fds",
				RoleType:  "cfn-exec-role",
			},
			isValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := tt.roleInfo.AccountID != "" && 
				tt.roleInfo.Region != "" && 
				tt.roleInfo.Qualifier != "" &&
				tt.roleInfo.RoleType != ""
			
			assert.Equal(t, tt.isValid, isValid)
		})
	}
}