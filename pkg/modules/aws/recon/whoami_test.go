package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWhoamiModuleRegistration(t *testing.T) {
	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "whoami")
	require.True(t, ok, "whoami module should be registered")
	require.NotNil(t, mod)
}

func TestWhoamiModuleMetadata(t *testing.T) {
	m := &AWSWhoamiModule{}
	assert.Equal(t, "whoami", m.ID())
	assert.Equal(t, "AWS Covert Whoami", m.Name())
	assert.Equal(t, plugin.PlatformAWS, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "stealth", m.OpsecLevel())

	authors := m.Authors()
	require.Len(t, authors, 1)
	assert.Equal(t, "Praetorian", authors[0])

	assert.NotEmpty(t, m.Description())
	assert.Contains(t, m.Description(), "Covert")

	refs := m.References()
	require.Len(t, refs, 2)
	assert.Contains(t, refs[0], "hackingthe.cloud")
}

func TestWhoamiModuleParameters(t *testing.T) {
	m := &AWSWhoamiModule{}
	params, err := plugin.ParametersFrom(m.Parameters())
	require.NoError(t, err)

	paramNames := make(map[string]bool)
	for _, p := range params {
		paramNames[p.Name] = true
	}

	assert.True(t, paramNames["profile"], "should have profile param")
	assert.True(t, paramNames["profile-dir"], "should have profile-dir param")
	assert.True(t, paramNames["action"], "should have action param")
}

func TestWhoamiSupportedResourceTypes(t *testing.T) {
	m := &AWSWhoamiModule{}
	types := m.SupportedResourceTypes()
	require.Len(t, types, 2)
	assert.Contains(t, types, "AWS::IAM::User")
	assert.Contains(t, types, "AWS::IAM::Role")
}

func TestExtractARNFromError(t *testing.T) {
	tests := []struct {
		name    string
		errMsg  string
		wantARN string
	}{
		{
			name:    "IAM user ARN",
			errMsg:  `User: arn:aws:iam::123456789012:user/alice is not authorized to perform: timestream:DescribeEndpoints`,
			wantARN: "arn:aws:iam::123456789012:user/alice",
		},
		{
			name:    "assumed role ARN",
			errMsg:  `User: arn:aws:sts::123456789012:assumed-role/my-role/session-name is not authorized`,
			wantARN: "arn:aws:sts::123456789012:assumed-role/my-role/session-name",
		},
		{
			name:    "no ARN in message",
			errMsg:  `connection timeout after 30s`,
			wantARN: "",
		},
		{
			name:    "empty error",
			errMsg:  "",
			wantARN: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractARNFromError(tt.errMsg)
			assert.Equal(t, tt.wantARN, got)
		})
	}
}

func TestAccountFromARN(t *testing.T) {
	tests := []struct {
		arn     string
		account string
	}{
		{"arn:aws:iam::123456789012:user/alice", "123456789012"},
		{"arn:aws:sts::987654321098:assumed-role/role/session", "987654321098"},
		{"invalid", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.arn, func(t *testing.T) {
			assert.Equal(t, tt.account, accountFromARN(tt.arn))
		})
	}
}
