package helpers

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/smithy-go/middleware"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequestAdmission_RetriesAndPagination(t *testing.T) {
	admissions, attempts := 0, 0
	cfg := admissionTestConfig(t, func(context.Context) error {
		admissions++
		return nil
	}, func(req *http.Request) (*http.Response, error) {
		attempts++
		assert.Equal(t, attempts, admissions)
		assert.NotEmpty(t, req.Header.Get("Authorization"))
		status, body := http.StatusOK, `{"Functions":[]}`
		switch attempts {
		case 1:
			status, body = http.StatusInternalServerError, `{"message":"retry"}`
		case 2:
			body = `{"Functions":[],"NextMarker":"page-2"}`
		case 3:
			assert.Equal(t, "page-2", req.URL.Query().Get("Marker"))
		}
		return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	})
	cfg.APIOptions = append(cfg.APIOptions, func(stack *middleware.Stack) error {
		ids := stack.Finalize.List()
		positions := map[string]int{}
		for i, id := range ids {
			positions[id] = i
		}
		assert.Less(t, positions["Retry"], positions["AurelianRequestAdmission"])
		assert.Less(t, positions["AurelianRequestAdmission"], positions["Signing"])
		return nil
	})

	paginator := lambda.NewListFunctionsPaginator(lambda.NewFromConfig(cfg), &lambda.ListFunctionsInput{})
	pages := 0
	for paginator.HasMorePages() {
		_, err := paginator.NextPage(context.Background())
		require.NoError(t, err)
		pages++
	}
	assert.Equal(t, 2, pages)
	assert.Equal(t, 3, attempts)
	assert.Equal(t, attempts, admissions)
}

func TestRequestAdmission_RejectionPreventsTransmission(t *testing.T) {
	attempts := 0
	cfg := admissionTestConfig(t, func(context.Context) error {
		return context.Canceled
	}, func(req *http.Request) (*http.Response, error) {
		attempts++
		return nil, context.Canceled
	})

	_, err := lambda.NewFromConfig(cfg).GetFunction(context.Background(), &lambda.GetFunctionInput{FunctionName: aws.String("test")})
	assert.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, attempts)
}

func TestRequestAdmission_NilHookPreservesDefault(t *testing.T) {
	attempts := 0
	cfg := admissionTestConfig(t, nil, func(req *http.Request) (*http.Response, error) {
		attempts++
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{}`)), Request: req}, nil
	})
	_, err := lambda.NewFromConfig(cfg).GetFunction(context.Background(), &lambda.GetFunctionInput{FunctionName: aws.String("test")})
	require.NoError(t, err)
	assert.Equal(t, 1, attempts)
}

func admissionTestConfig(t *testing.T, hook func(context.Context) error, send admissionHTTPClient) aws.Config {
	t.Helper()
	cfg, err := NewAWSConfig(AWSConfigInput{
		Region:        "us-east-1",
		BeforeRequest: hook,
		LoadOptionFns: []func(*config.LoadOptions) error{
			config.WithSharedConfigFiles([]string{}),
			config.WithSharedCredentialsFiles([]string{}),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
			config.WithHTTPClient(send),
			config.WithRetryer(func() aws.Retryer {
				return retry.NewStandard(func(opts *retry.StandardOptions) {
					opts.MaxAttempts = 2
					opts.Backoff = retry.BackoffDelayerFunc(func(int, error) (time.Duration, error) { return 0, nil })
				})
			}),
		},
	})
	require.NoError(t, err)
	return cfg
}

type admissionHTTPClient func(*http.Request) (*http.Response, error)

func (send admissionHTTPClient) Do(req *http.Request) (*http.Response, error) { return send(req) }
