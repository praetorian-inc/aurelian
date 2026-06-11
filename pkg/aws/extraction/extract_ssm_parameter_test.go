package extraction

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
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

func TestExtractSSMParameter_UnknownTypeSkipped(t *testing.T) {
	// Any type other than String/StringList must be rejected at the guard.
	// This ensures a future refactor cannot accidentally allow unknown types
	// by changing the guard from "allow-list" to "block SecureString only".
	// Missing/nil Properties must also be rejected — never call GetParameter
	// on a parameter whose type is unknown.
	cases := []struct {
		name       string
		properties map[string]any
	}{
		{"custom type", map[string]any{"Name": "/test/param", "Type": "CustomType"}},
		{"nil properties", nil},
		{"missing type key", map[string]any{"Name": "/test/param"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := output.AWSResource{
				ResourceType: "AWS::SSM::Parameter",
				ResourceID:   "/test/param",
				Region:       "us-east-1",
				Properties:   tc.properties,
			}

			out := pipeline.New[output.ScanInput]()
			go func() {
				defer out.Close()
				err := extractSSMParameter(extractContext{
					Context:   context.Background(),
					AWSConfig: aws.Config{},
				}, r, out)
				assert.NoError(t, err)
			}()

			items, err := out.Collect()
			require.NoError(t, err)
			assert.Empty(t, items, "type %q must not produce scan inputs", tc.name)
		})
	}
}

// fakeSSMTransport is an http.RoundTripper that returns a hardcoded GetParameter response.
type fakeSSMTransport struct {
	body string
}

func (f *fakeSSMTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}},
		Body:       io.NopCloser(strings.NewReader(f.body)),
	}, nil
}

func fakeGetParameterResponse(paramType, value string) string {
	resp := map[string]any{
		"Parameter": map[string]any{
			"Name":  "/test/param",
			"Type":  paramType,
			"Value": value,
		},
	}
	b, _ := json.Marshal(resp)
	return string(b)
}

func fakeAWSConfigWithResponse(body string) aws.Config {
	return aws.Config{
		Region:      "us-east-1",
		Credentials: aws.AnonymousCredentials{},
		HTTPClient:  &http.Client{Transport: &fakeSSMTransport{body: body}},
	}
}

func TestExtractSSMParameter_SecondGuard_SecureStringFromAPI(t *testing.T) {
	// The extractor has a defense-in-depth guard: even if Properties["Type"] says "String"
	// (e.g., mislabeled during enumeration), if the API returns SecureString, skip it.
	r := output.AWSResource{
		ResourceType: "AWS::SSM::Parameter",
		ResourceID:   "/test/param",
		Region:       "us-east-1",
		Properties: map[string]any{
			"Name": "/test/param",
			"Type": "String", // passes first guard
		},
	}

	cfg := fakeAWSConfigWithResponse(fakeGetParameterResponse("SecureString", "secret-value"))

	out := pipeline.New[output.ScanInput]()
	go func() {
		defer out.Close()
		err := extractSSMParameter(extractContext{
			Context:   context.Background(),
			AWSConfig: cfg,
		}, r, out)
		assert.NoError(t, err, "SecureString from API should be silently skipped, not error")
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	assert.Empty(t, items, "SecureString returned by API must not produce scan inputs even when Properties say String")
}

func TestExtractSSMParameter_EmptyValueSkipped(t *testing.T) {
	r := output.AWSResource{
		ResourceType: "AWS::SSM::Parameter",
		ResourceID:   "/test/param",
		Region:       "us-east-1",
		Properties: map[string]any{
			"Name": "/test/param",
			"Type": "String",
		},
	}

	cfg := fakeAWSConfigWithResponse(fakeGetParameterResponse("String", ""))

	out := pipeline.New[output.ScanInput]()
	go func() {
		defer out.Close()
		err := extractSSMParameter(extractContext{
			Context:   context.Background(),
			AWSConfig: cfg,
		}, r, out)
		assert.NoError(t, err)
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	assert.Empty(t, items, "parameter with empty value must not produce scan inputs")
}

func TestExtractSSMParameter_ValueIsSent(t *testing.T) {
	const secretValue = "AKIAIOSFODNN7EXAMPLE"
	cases := []struct {
		paramType string
		value     string
	}{
		{"String", secretValue},
		{"StringList", "val1,val2," + secretValue},
	}
	for _, tc := range cases {
		t.Run(tc.paramType, func(t *testing.T) {
			r := output.AWSResource{
				ResourceType: "AWS::SSM::Parameter",
				ResourceID:   "/test/param",
				Region:       "us-east-1",
				Properties: map[string]any{
					"Name": "/test/param",
					"Type": tc.paramType,
				},
			}

			cfg := fakeAWSConfigWithResponse(fakeGetParameterResponse(tc.paramType, tc.value))

			out := pipeline.New[output.ScanInput]()
			go func() {
				defer out.Close()
				err := extractSSMParameter(extractContext{
					Context:   context.Background(),
					AWSConfig: cfg,
				}, r, out)
				assert.NoError(t, err)
			}()

			items, err := out.Collect()
			require.NoError(t, err)
			require.Len(t, items, 1, "%s parameter must produce exactly one scan input", tc.paramType)
			assert.Equal(t, []byte(tc.value), items[0].Content)
			assert.Equal(t, "Parameter", items[0].Label)
		})
	}
}
