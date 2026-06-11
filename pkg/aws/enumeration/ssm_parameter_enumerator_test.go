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

func TestEnumerator_DispatchesSSMParameterToCustomEnumerator(t *testing.T) {
	// Enumerator.List("AWS::SSM::Parameter", ...) must route to SSMParameterEnumerator,
	// not fall through to CloudControl. CloudControl does not support AWS::SSM::Parameter,
	// so a CloudControl dispatch would return a "resource type not supported" error.
	// SSMParameterEnumerator.EnumerateAll returns "no regions configured" with empty opts —
	// a distinct error that proves the custom enumerator was called.
	e := NewEnumerator(plugin.AWSCommonRecon{Regions: []string{}})
	out := pipeline.New[output.AWSResource]()
	err := e.List("AWS::SSM::Parameter", out)
	out.Close()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no regions configured",
		"expected SSMParameterEnumerator dispatch; got: %v", err)
}
