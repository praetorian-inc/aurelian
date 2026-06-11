package enumeration

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
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

func TestSSMParameterEnumerator_EnumerateByARN_Errors(t *testing.T) {
	provider := NewAWSConfigProvider(plugin.AWSCommonRecon{})
	enum := NewSSMParameterEnumerator(plugin.AWSCommonRecon{}, provider)
	out := pipeline.New[output.AWSResource]()

	t.Run("bad ARN returns error", func(t *testing.T) {
		err := enum.EnumerateByARN("not-an-arn", out)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse ARN")
	})

	t.Run("non-parameter resource returns error", func(t *testing.T) {
		// Valid SSM ARN but resource type is "document/", not "parameter/"
		err := enum.EnumerateByARN("arn:aws:ssm:us-east-1:123456789012:document/MyDoc", out)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid SSM parameter ARN resource")
	})

	t.Run("ARN missing region returns error", func(t *testing.T) {
		// Construct a valid ARN with empty region
		err := enum.EnumerateByARN("arn:aws:ssm::123456789012:parameter/my-param", out)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing region")
	})
}
