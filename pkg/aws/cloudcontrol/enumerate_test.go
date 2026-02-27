package cloudcontrol

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testSupportedTypes = []string{
	"AWS::S3::Bucket",
	"AWS::EC2::Instance",
	"AWS::Lambda::Function",
}

func TestResolveResourceTypes_All(t *testing.T) {
	// nil requested → returns all supported
	types, err := resolveResourceTypes(nil, testSupportedTypes)
	require.NoError(t, err)
	assert.Equal(t, testSupportedTypes, types)
}

func TestResolveResourceTypes_AllExplicit(t *testing.T) {
	types, err := resolveResourceTypes([]string{"all"}, testSupportedTypes)
	require.NoError(t, err)
	assert.Equal(t, testSupportedTypes, types)
}

func TestResolveResourceTypes_Specific(t *testing.T) {
	types, err := resolveResourceTypes([]string{"AWS::S3::Bucket", "AWS::Lambda::Function"}, testSupportedTypes)
	require.NoError(t, err)
	assert.Equal(t, []string{"AWS::S3::Bucket", "AWS::Lambda::Function"}, types)
}

func TestResolveResourceTypes_Invalid(t *testing.T) {
	_, err := resolveResourceTypes([]string{"AWS::Fake::Thing"}, testSupportedTypes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported resource type")
}

func TestResolveResourceTypes_Empty(t *testing.T) {
	types, err := resolveResourceTypes([]string{}, testSupportedTypes)
	require.NoError(t, err)
	assert.Equal(t, testSupportedTypes, types)
}

func TestGetAWSConfig_Caching(t *testing.T) {
	cc := &CloudControlLister{
		AWSConfigs: make(map[string]*aws.Config),
	}

	// Pre-populate cache with a known config
	testCfg := &aws.Config{Region: "us-east-1"}
	cc.AWSConfigs["us-east-1"] = testCfg

	// Should return cached config
	cfg, err := cc.getAWSConfig("us-east-1")
	require.NoError(t, err)
	assert.Same(t, testCfg, cfg)
}

func TestGetAccountID_Caching(t *testing.T) {
	cc := &CloudControlLister{
		AWSConfigs: make(map[string]*aws.Config),
		accountID:  "123456789012",
	}

	// Force the Once to be already done by setting accountID directly
	cc.accountIDOnce.Do(func() {})

	// Should return cached account ID without making STS call
	id, err := cc.getAccountID("us-east-1")
	require.NoError(t, err)
	assert.Equal(t, "123456789012", id)

	// Second call returns same value
	id2, err := cc.getAccountID("us-west-2")
	require.NoError(t, err)
	assert.Equal(t, id, id2)
}
