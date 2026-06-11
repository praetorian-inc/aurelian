//go:build integration

package enumeration

import (
	"fmt"
	"strings"
	"testing"

	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSMParameterEnumerator(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/find-secrets")
	fixture.Setup()

	provider := NewAWSConfigProvider(plugin.AWSCommonRecon{
		Regions:     []string{"us-east-2"},
		Concurrency: 2,
	})
	enum := NewSSMParameterEnumerator(plugin.AWSCommonRecon{
		Regions:     []string{"us-east-2"},
		Concurrency: 2,
	}, provider)

	results, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
		return enum.EnumerateAll(out)
	})
	require.NoError(t, err)

	paramName := fixture.Output("ssm_parameter_name")
	paramARN := fixture.Output("ssm_parameter_arn")
	secureName := fixture.Output("ssm_securestring_name")

	t.Run("String parameter is enumerated", func(t *testing.T) {
		require.True(t, resultsContainResourceID(results, paramName),
			"expected String parameter %q in results", paramName)
	})

	t.Run("SecureString parameter is absent", func(t *testing.T) {
		assert.False(t, resultsContainResourceID(results, secureName),
			"SecureString parameter %q must not be enumerated", secureName)
	})

	t.Run("resource shape is correct", func(t *testing.T) {
		var param *output.AWSResource
		for i := range results {
			if results[i].ResourceID == paramName {
				param = &results[i]
				break
			}
		}
		require.NotNil(t, param)
		require.NotNil(t, param.Properties, "expected Properties map to be populated")
		assert.Equal(t, "AWS::SSM::Parameter", param.ResourceType)
		assert.Equal(t, paramARN, param.ARN)
		assert.NotEmpty(t, param.AccountRef)
		assert.Equal(t, "us-east-2", param.Region)
		assert.Equal(t, "String", param.Properties["Type"])
		assert.Equal(t, paramName, param.Properties["Name"], "Properties[Name] should equal the parameter name")
	})

	t.Run("EnumerateByARN round-trips", func(t *testing.T) {
		single, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enum.EnumerateByARN(paramARN, out)
		})
		require.NoError(t, err)
		require.Len(t, single, 1)
		assert.Equal(t, paramName, single[0].ResourceID)
		assert.Equal(t, paramARN, single[0].ARN)
	})

	t.Run("EnumerateByARN filters SecureString", func(t *testing.T) {
		// Build the SecureString ARN from the String param ARN (same account + region).
		parsed, err := awsarn.Parse(paramARN)
		require.NoError(t, err)
		secureARN := fmt.Sprintf("arn:aws:ssm:%s:%s:parameter/%s",
			parsed.Region, parsed.AccountID, strings.TrimPrefix(secureName, "/"))

		secureResults, err := collectResources(func(out *pipeline.P[output.AWSResource]) error {
			return enum.EnumerateByARN(secureARN, out)
		})
		require.NoError(t, err)
		assert.Empty(t, secureResults, "EnumerateByARN must not return SecureString parameters")
	})

	t.Run("all results are correct resource type", func(t *testing.T) {
		for _, r := range results {
			assert.Equal(t, "AWS::SSM::Parameter", r.ResourceType)
		}
	})
}
