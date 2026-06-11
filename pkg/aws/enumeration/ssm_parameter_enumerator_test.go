package enumeration

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeDescribeParamsTransport struct{ body string }

func (f *fakeDescribeParamsTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}},
		Body:       io.NopCloser(strings.NewReader(f.body)),
	}, nil
}

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

	t.Run("SecureString parameter is filtered", func(t *testing.T) {
		// Inject a fake HTTP transport so DescribeParameters returns a SecureString parameter
		// without hitting real AWS. The provider.configs map is package-internal and accessible here.
		body := `{"Parameters":[{"Name":"/prefix/secure-param","Type":"SecureString","Tier":"Standard","DataType":"text"}]}`
		fakeCfg := aws.Config{
			HTTPClient: &http.Client{Transport: &fakeDescribeParamsTransport{body: body}},
			Region:     "us-east-1",
		}
		secureProvider := NewAWSConfigProvider(plugin.AWSCommonRecon{})
		secureProvider.configs["us-east-1"] = &fakeCfg
		secureEnum := NewSSMParameterEnumerator(plugin.AWSCommonRecon{}, secureProvider)

		secureOut := pipeline.New[output.AWSResource]()
		err := secureEnum.EnumerateByARN("arn:aws:ssm:us-east-1:123456789012:parameter/prefix/secure-param", secureOut)
		require.NoError(t, err)

		secureOut.Close()
		results, err := secureOut.Collect()
		require.NoError(t, err)
		assert.Empty(t, results, "EnumerateByARN must not return SecureString parameters")
	})

	t.Run("parameter with empty name is skipped", func(t *testing.T) {
		// AWS always populates Name, but guard against a nil pointer returning "".
		body := `{"Parameters":[{"Type":"String","Tier":"Standard"}]}`
		fakeCfg := aws.Config{
			HTTPClient: &http.Client{Transport: &fakeDescribeParamsTransport{body: body}},
			Region:     "us-east-1",
		}
		emptyNameProvider := NewAWSConfigProvider(plugin.AWSCommonRecon{})
		emptyNameProvider.configs["us-east-1"] = &fakeCfg
		emptyEnum := NewSSMParameterEnumerator(plugin.AWSCommonRecon{}, emptyNameProvider)

		emptyOut := pipeline.New[output.AWSResource]()
		err := emptyEnum.EnumerateByARN("arn:aws:ssm:us-east-1:123456789012:parameter/my-param", emptyOut)
		require.NoError(t, err)

		emptyOut.Close()
		results, err := emptyOut.Collect()
		require.NoError(t, err)
		assert.Empty(t, results, "parameter with empty name must be skipped")
	})
}

func TestSSMParameterEnumerator_EnumerateByARN_ParameterNames(t *testing.T) {
	cases := []struct {
		name         string
		arn          string
		apiName      string // Name the fake API returns
		wantID       string
		wantARNSuffix string
	}{
		{
			name:          "hierarchical parameter",
			arn:           "arn:aws:ssm:us-east-1:123456789012:parameter/my/nested/param",
			apiName:       "/my/nested/param",
			wantID:        "/my/nested/param",
			wantARNSuffix: "parameter/my/nested/param",
		},
		{
			name:          "top-level (non-hierarchical) parameter",
			arn:           "arn:aws:ssm:us-east-1:123456789012:parameter/FlatParam",
			apiName:       "FlatParam",
			wantID:        "FlatParam",
			wantARNSuffix: "parameter/FlatParam",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"Parameters":[{"Name":"` + tc.apiName + `","Type":"String","Tier":"Standard"}]}`
			fakeCfg := aws.Config{
				HTTPClient: &http.Client{Transport: &fakeDescribeParamsTransport{body: body}},
				Region:     "us-east-1",
			}
			provider := NewAWSConfigProvider(plugin.AWSCommonRecon{})
			provider.configs["us-east-1"] = &fakeCfg
			enum := NewSSMParameterEnumerator(plugin.AWSCommonRecon{}, provider)

			out := pipeline.New[output.AWSResource]()
			err := enum.EnumerateByARN(tc.arn, out)
			require.NoError(t, err)
			out.Close()
			results, err := out.Collect()
			require.NoError(t, err)
			require.Len(t, results, 1)
			assert.Equal(t, tc.wantID, results[0].ResourceID)
			assert.True(t, strings.HasSuffix(results[0].ARN, tc.wantARNSuffix),
				"ARN %q should end with %q", results[0].ARN, tc.wantARNSuffix)
		})
	}
}

func TestSSMParameterEnumerator_ListParametersInRegion(t *testing.T) {
	t.Run("emits parameter with correct shape", func(t *testing.T) {
		body := `{"Parameters":[{"Name":"/my/param","Type":"String","Tier":"Standard","DataType":"text"}]}`
		fakeCfg := aws.Config{
			HTTPClient: &http.Client{Transport: &fakeDescribeParamsTransport{body: body}},
			Region:     "us-east-1",
		}
		provider := NewAWSConfigProvider(plugin.AWSCommonRecon{})
		provider.configs["us-east-1"] = &fakeCfg
		enum := NewSSMParameterEnumerator(plugin.AWSCommonRecon{}, provider)

		out := pipeline.New[output.AWSResource]()
		var listErr error
		go func() {
			defer out.Close()
			listErr = enum.listParametersInRegion("us-east-1", "123456789012", out)
		}()
		results, err := out.Collect()
		require.NoError(t, err)
		require.NoError(t, listErr)
		require.Len(t, results, 1)
		r := results[0]
		assert.Equal(t, "AWS::SSM::Parameter", r.ResourceType)
		assert.Equal(t, "/my/param", r.ResourceID)
		assert.Equal(t, "arn:aws:ssm:us-east-1:123456789012:parameter/my/param", r.ARN)
		assert.Equal(t, "123456789012", r.AccountRef)
		assert.Equal(t, "us-east-1", r.Region)
		assert.Equal(t, "String", r.Properties["Type"])
		assert.Equal(t, "/my/param", r.Properties["Name"])
	})

	t.Run("skips parameter with empty name", func(t *testing.T) {
		body := `{"Parameters":[{"Type":"String","Tier":"Standard"}]}`
		fakeCfg := aws.Config{
			HTTPClient: &http.Client{Transport: &fakeDescribeParamsTransport{body: body}},
			Region:     "us-east-1",
		}
		provider := NewAWSConfigProvider(plugin.AWSCommonRecon{})
		provider.configs["us-east-1"] = &fakeCfg
		enum := NewSSMParameterEnumerator(plugin.AWSCommonRecon{}, provider)

		out := pipeline.New[output.AWSResource]()
		go func() {
			defer out.Close()
			_ = enum.listParametersInRegion("us-east-1", "123456789012", out)
		}()
		results, err := out.Collect()
		require.NoError(t, err)
		assert.Empty(t, results, "parameter with empty name must be skipped")
	})
}
