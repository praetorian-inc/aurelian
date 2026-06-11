package enumeration

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSMParameterEnumerator_ResourceType(t *testing.T) {
	provider := NewAWSConfigProvider(plugin.AWSCommonRecon{
		Regions:     []string{"us-east-1"},
		Concurrency: 2,
	})
	enum := NewSSMParameterEnumerator(plugin.AWSCommonRecon{
		Regions:     []string{"us-east-1"},
		Concurrency: 2,
	}, provider)

	assert.Equal(t, "AWS::SSM::Parameter", enum.ResourceType())
}

func TestNewEnumerator_RegistersSSMParameter(t *testing.T) {
	e := NewEnumerator(plugin.AWSCommonRecon{Regions: []string{"us-east-1"}})
	enumerator, ok := e.enumerators["AWS::SSM::Parameter"]
	require.True(t, ok, "NewEnumerator should register an enumerator for AWS::SSM::Parameter")
	assert.Equal(t, "AWS::SSM::Parameter", enumerator.ResourceType())
}
