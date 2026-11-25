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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Unlike request_admission_test.go, these tests do NOT replace the SDK backoff
// with zero delays. Observe the production retryer and the actual HTTP attempts.
func TestAWSRetryBackoff_RequestsWaitForSDKDelay(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var sent []time.Time
			admissions := 0
			client := defaultRetryTestClient(t, func(context.Context) error {
				admissions++ // No pacing: the SDK alone must supply the backoff.
				return nil
			}, func(req *http.Request) (*http.Response, error) {
				sent = append(sent, time.Now())
				assert.Equal(t, len(sent), admissions)
				return retryTestResponse(req, status), nil
			})
			retryer := observeDefaultRetryer(t, client)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			_, err := client.GetFunction(ctx, &lambda.GetFunctionInput{FunctionName: aws.String("example")}, func(o *lambda.Options) {
				o.Retryer = retryer
			})
			var exhausted *retry.MaxAttemptsError
			require.ErrorAs(t, err, &exhausted)
			require.Len(t, sent, 3)
			require.Equal(t, []int{1, 2}, retryer.attempts)
			require.Len(t, retryer.delays, 2)
			for i, delay := range retryer.delays {
				// Full jitter need not increase monotonically; its exponential
				// windows are 0–2s, then 0–4s (legacy SDK retry behavior).
				assert.Positive(t, delay)
				assert.LessOrEqual(t, delay, time.Second*time.Duration(1<<(i+1)))
				elapsed := sent[i+1].Sub(sent[i])
				assert.GreaterOrEqual(t, elapsed+time.Millisecond, delay)
				t.Logf("retry %d: SDK delay=%s, actual attempt gap=%s", i+1, delay, elapsed)
			}
		})
	}
}

func TestAWSRetryBackoff_CappedAtTwentySeconds(t *testing.T) {
	client := defaultRetryTestClient(t, nil, func(*http.Request) (*http.Response, error) {
		t.Fatal("delay calculation must not send requests")
		return nil, nil
	})
	retryer := observeDefaultRetryer(t, client)
	delay, err := retryer.RetryDelay(30, nil)
	require.NoError(t, err)
	assert.Equal(t, 20*time.Second, delay)
}

func TestAWSRetryBackoff_CancellationStopsRetries(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	attempts := 0
	client := defaultRetryTestClient(t, nil, func(req *http.Request) (*http.Response, error) {
		attempts++
		return retryTestResponse(req, http.StatusInternalServerError), nil
	})
	retryer := observeDefaultRetryer(t, client)
	retryer.cancel = cancel // Cancel after the SDK chooses its delay, before sleeping.
	_, err := client.GetFunction(ctx, &lambda.GetFunctionInput{FunctionName: aws.String("example")}, func(o *lambda.Options) {
		o.Retryer = retryer
	})
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, attempts)
	assert.Len(t, retryer.delays, 1)
}

func TestAWSRetryBackoff_AccessDeniedIsNotRetried(t *testing.T) {
	attempts := 0
	client := defaultRetryTestClient(t, nil, func(req *http.Request) (*http.Response, error) {
		attempts++
		return retryTestResponse(req, http.StatusForbidden), nil
	})
	_, err := client.GetFunction(context.Background(), &lambda.GetFunctionInput{FunctionName: aws.String("example")})
	require.Error(t, err)
	assert.Equal(t, 1, attempts)
}

func defaultRetryTestClient(t *testing.T, hook func(context.Context) error, send admissionHTTPClient) *lambda.Client {
	t.Helper()
	t.Setenv("AWS_MAX_ATTEMPTS", "")
	t.Setenv("AWS_NEW_RETRIES_2026", "false")
	cfg, err := NewAWSConfig(AWSConfigInput{
		Region:        "us-east-1",
		BeforeRequest: hook,
		LoadOptionFns: []func(*config.LoadOptions) error{
			config.WithSharedConfigFiles([]string{}),
			config.WithSharedCredentialsFiles([]string{}),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("test", "test", "")),
			config.WithHTTPClient(send),
		},
	})
	require.NoError(t, err)
	assert.Equal(t, aws.RetryModeAdaptive, cfg.RetryMode)
	return lambda.NewFromConfig(cfg)
}

func observeDefaultRetryer(t *testing.T, client *lambda.Client) *observedRetryer {
	t.Helper()
	r := client.Options().Retryer
	require.IsType(t, &retry.AdaptiveMode{}, r)
	assert.Equal(t, 3, r.MaxAttempts())
	return &observedRetryer{RetryerV2: r.(aws.RetryerV2)}
}

type observedRetryer struct {
	aws.RetryerV2
	attempts []int
	delays   []time.Duration
	cancel   context.CancelFunc
}

func (r *observedRetryer) RetryDelay(attempt int, err error) (time.Duration, error) {
	delay, delayErr := r.RetryerV2.RetryDelay(attempt, err)
	r.attempts = append(r.attempts, attempt)
	r.delays = append(r.delays, delay)
	if r.cancel != nil {
		r.cancel()
	}
	return delay, delayErr
}

func retryTestResponse(req *http.Request, status int) *http.Response {
	header := http.Header{}
	switch status {
	case http.StatusTooManyRequests:
		header.Set("X-Amzn-Errortype", "TooManyRequestsException")
	case http.StatusForbidden:
		header.Set("X-Amzn-Errortype", "AccessDeniedException")
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(`{"message":"test failure"}`)), Request: req}
}
