package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindSecretsModuleMetadata(t *testing.T) {
	m := &AWSFindSecretsModule{}

	assert.Equal(t, "find-secrets", m.ID())
	assert.Equal(t, "AWS Find Secrets", m.Name())
	assert.Equal(t, plugin.PlatformAWS, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "moderate", m.OpsecLevel())

	authors := m.Authors()
	require.Len(t, authors, 1)
	assert.Equal(t, "Praetorian", authors[0])

	assert.NotEmpty(t, m.Description())
	assert.NotEmpty(t, m.References())
}

func TestFindSecretsSupportedResourceTypes(t *testing.T) {
	m := &AWSFindSecretsModule{}
	types := m.SupportedResourceTypes()

	expected := []string{
		"AWS::EC2::Instance",
		"AWS::Lambda::Function",
		"AWS::CloudFormation::Stack",
		"AWS::Logs::LogGroup",
		"AWS::ECS::TaskDefinition",
		"AWS::SSM::Document",
		"AWS::StepFunctions::StateMachine",
	}

	assert.Equal(t, expected, types)
}

func TestFindSecretsParameters(t *testing.T) {
	m := &AWSFindSecretsModule{}
	params, err := plugin.ParametersFrom(m.Parameters())
	require.NoError(t, err)

	paramNames := make(map[string]bool)
	for _, p := range params {
		paramNames[p.Name] = true
	}

	assert.True(t, paramNames["profile"], "should have profile param")
	assert.True(t, paramNames["regions"], "should have regions param")
	assert.True(t, paramNames["concurrency"], "should have concurrency param")
	assert.True(t, paramNames["db-path"], "should have db-path param")
	assert.True(t, paramNames["max-events"], "should have max-events param")
	assert.True(t, paramNames["max-streams"], "should have max-streams param")
}
