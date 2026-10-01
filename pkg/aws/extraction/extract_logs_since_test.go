package extraction

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeLogsTransport answers DescribeLogStreams with two streams and
// FilterLogEvents with one event, recording every FilterLogEvents body.
type fakeLogsTransport struct {
	mu      sync.Mutex
	filters []map[string]any
}

func (f *fakeLogsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(req.Body)
	resp := `{"logStreams":[{"logStreamName":"s1"},{"logStreamName":"s2"}]}`
	if strings.HasSuffix(req.Header.Get("X-Amz-Target"), ".FilterLogEvents") {
		var input map[string]any
		if err := json.Unmarshal(body, &input); err == nil {
			f.mu.Lock()
			f.filters = append(f.filters, input)
			f.mu.Unlock()
		}
		resp = `{"events":[{"logStreamName":"s1","message":"AKIA-looking secret","timestamp":1}]}`
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}},
		Body:       io.NopCloser(strings.NewReader(resp)),
		Request:    req,
	}, nil
}

func runExtractLogs(t *testing.T, cfg Config) ([]output.ScanInput, []map[string]any) {
	t.Helper()
	fake := &fakeLogsTransport{}
	ctx := extractContext{
		Context: context.Background(),
		AWSConfig: aws.Config{
			Region:      "us-east-1",
			Credentials: aws.AnonymousCredentials{},
			HTTPClient:  &http.Client{Transport: fake},
		},
		Config:      cfg,
		Concurrency: 2,
	}
	r := output.AWSResource{
		ResourceType: "AWS::Logs::LogGroup",
		ResourceID:   "/app/api",
		Region:       "us-east-1",
		Properties:   map[string]any{"LogGroupName": "/app/api"},
	}

	out := pipeline.New[output.ScanInput]()
	var extractErr error
	go func() {
		extractErr = extractLogs(ctx, r, out)
		out.Close()
	}()
	items, err := out.Collect()
	require.NoError(t, err)
	require.NoError(t, extractErr)
	return items, fake.filters
}

func TestExtractLogs_LogsSinceSetsStartTimeWithLagBuffer(t *testing.T) {
	since := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

	items, filters := runExtractLogs(t, Config{MaxEvents: 100, MaxStreams: 10, LogsSince: since})

	require.Len(t, filters, 2, "one FilterLogEvents request per stream")
	want := since.Add(-6 * time.Hour).UnixMilli()
	for _, f := range filters {
		require.Contains(t, f, "startTime")
		assert.EqualValues(t, want, f["startTime"], "startTime is logs-since minus the 6h lag buffer, in milliseconds")
	}
	assert.Len(t, items, 2, "events are still extracted")
}

func TestExtractLogs_UnsetLogsSinceSendsNoStartTime(t *testing.T) {
	items, filters := runExtractLogs(t, Config{MaxEvents: 100, MaxStreams: 10})

	require.Len(t, filters, 2)
	for _, f := range filters {
		assert.NotContains(t, f, "startTime", "without logs-since the request reads from the start of each stream, as before")
	}
	assert.Len(t, items, 2)
}

func TestExtract_LogsSinceNeverSkipsAResource(t *testing.T) {
	var called bool
	mustRegister("AWS::UnitTest::LogsSinceType", "records", func(ec extractContext, r output.AWSResource, out *pipeline.P[output.ScanInput]) error {
		called = true
		out.Send(output.ScanInput{ResourceID: r.ResourceID, Label: "ok", Content: []byte("content")})
		return nil
	})

	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	ex := NewAWSExtractor(plugin.AWSCommonRecon{Concurrency: 1}, Config{LogsSince: time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)})
	out := pipeline.New[output.ScanInput]()
	go func() {
		defer out.Close()
		assert.NoError(t, ex.Extract(output.AWSResource{ResourceType: "AWS::UnitTest::LogsSinceType", ResourceID: "r1", Region: "us-east-1", LastModified: &old}, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	assert.True(t, called, "logs-since must not skip a resource, even one last modified long before it")
	assert.Len(t, items, 1)
}
