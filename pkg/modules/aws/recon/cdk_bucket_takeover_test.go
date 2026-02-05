package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCDKBucketTakeoverModule_Metadata(t *testing.T) {
	m := &CDKBucketTakeoverModule{}

	assert.Equal(t, "cdk-bucket-takeover", m.ID())
	assert.Equal(t, "CDK Bucket Takeover Detection", m.Name())
	assert.Contains(t, m.Description(), "CDK S3 bucket takeover vulnerabilities")
	assert.Equal(t, plugin.PlatformAWS, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "safe", m.OpsecLevel())
	assert.Equal(t, []string{"Praetorian"}, m.Authors())
	assert.Contains(t, m.References()[0], "aquasec.com")
}

func TestCDKBucketTakeoverModule_Parameters(t *testing.T) {
	m := &CDKBucketTakeoverModule{}
	params := m.Parameters()

	// Should have profile, regions, and qualifiers parameters
	require.GreaterOrEqual(t, len(params), 3)

	paramNames := make(map[string]bool)
	for _, p := range params {
		paramNames[p.Name] = true
	}

	assert.True(t, paramNames["profile"], "should have profile parameter")
	assert.True(t, paramNames["regions"], "should have regions parameter")
	assert.True(t, paramNames["cdk-qualifiers"], "should have cdk-qualifiers parameter")
}

func TestCDKBucketTakeoverModule_Registration(t *testing.T) {
	// Verify module is registered in plugin registry
	m, exists := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "cdk-bucket-takeover")
	require.True(t, exists, "module should be registered")
	require.NotNil(t, m, "module should not be nil")

	cdkModule, ok := m.(*CDKBucketTakeoverModule)
	require.True(t, ok, "should be CDKBucketTakeoverModule type")
	assert.Equal(t, "cdk-bucket-takeover", cdkModule.ID())
}
