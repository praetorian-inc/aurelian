package extraction

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractors_SSMParameterRegistered(t *testing.T) {
	extractors := getExtractors("AWS::SSM::Parameter")
	require.NotEmpty(t, extractors, "expected extractors registered for AWS::SSM::Parameter")

	var found bool
	for _, e := range extractors {
		if e.Name == "ssm-parameter" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected ssm-parameter extractor registered for AWS::SSM::Parameter")
}

func TestExtractSSMParameter_SecureStringSkipped(t *testing.T) {
	r := output.AWSResource{
		ResourceType: "AWS::SSM::Parameter",
		ResourceID:   "/test/param",
		Region:       "us-east-1",
		Properties: map[string]any{
			"Name": "/test/param",
			"Type": "SecureString",
		},
	}

	out := pipeline.New[output.ScanInput]()
	go func() {
		defer out.Close()
		err := extractSSMParameter(extractContext{
			Context:   context.Background(),
			AWSConfig: aws.Config{},
		}, r, out)
		// assert (not require) — require.FailNow panics in a non-test goroutine.
		assert.NoError(t, err)
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	assert.Empty(t, items, "SecureString parameters must not produce scan inputs")
}

func TestExtractSSMParameter_GuardAllowsStringAndStringList(t *testing.T) {
	// Proves that String and StringList pass the SecureString guard and reach GetParameter.
	// With a zero aws.Config the API call fails — an error return (not nil) is proof
	// the guard did NOT short-circuit. If the guard incorrectly blocked these types it
	// would return nil and this test would fail.
	for _, paramType := range []string{"String", "StringList"} {
		t.Run(paramType, func(t *testing.T) {
			r := output.AWSResource{
				ResourceType: "AWS::SSM::Parameter",
				ResourceID:   "/test/param",
				Region:       "us-east-1",
				Properties:   map[string]any{"Name": "/test/param", "Type": paramType},
			}
			out := pipeline.New[output.ScanInput]()
			err := extractSSMParameter(extractContext{
				Context:   context.Background(),
				AWSConfig: aws.Config{},
			}, r, out)
			out.Close()
			assert.Error(t, err, "%s type should reach GetParameter and return an API error, not be blocked by the guard", paramType)
		})
	}
}
