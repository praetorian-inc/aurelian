package enumeration

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fakeAccountID = "123456789012"

type fakeAWSResponse struct {
	status int
	body   string
}

// fakeAWS answers SDK requests at the HTTP layer, routed by operation name
// (X-Amz-Target for JSON protocols, Action for query protocols), and records
// every request body so tests can assert what was sent.
type fakeAWS struct {
	t        *testing.T
	mu       sync.Mutex
	handlers map[string]func(body string) fakeAWSResponse
	calls    map[string][]string
}

func newFakeAWS(t *testing.T) *fakeAWS {
	return &fakeAWS{t: t, handlers: map[string]func(string) fakeAWSResponse{}, calls: map[string][]string{}}
}

func (f *fakeAWS) on(operation string, h func(body string) fakeAWSResponse) {
	f.handlers[operation] = h
}

func (f *fakeAWS) reply(operation, body string) {
	f.on(operation, func(string) fakeAWSResponse { return fakeAWSResponse{status: http.StatusOK, body: body} })
}

func (f *fakeAWS) fail(operation string, status int, body string) {
	f.on(operation, func(string) fakeAWSResponse { return fakeAWSResponse{status: status, body: body} })
}

func (f *fakeAWS) requests(operation string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls[operation]...)
}

func (f *fakeAWS) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
	}

	query := false
	operation := req.Header.Get("X-Amz-Target")
	if _, op, ok := strings.Cut(operation, "."); ok {
		operation = op
	} else if form, err := url.ParseQuery(string(body)); err == nil {
		operation = form.Get("Action")
		query = true
	}

	f.mu.Lock()
	f.calls[operation] = append(f.calls[operation], string(body))
	h, ok := f.handlers[operation]
	f.mu.Unlock()

	resp := fakeAWSResponse{status: http.StatusBadRequest, body: `{"__type":"UnexpectedCall"}`}
	if ok {
		resp = h(string(body))
	} else {
		assert.Fail(f.t, "unexpected AWS call", "operation %q", operation)
	}

	contentType := "application/x-amz-json-1.1"
	if query {
		contentType = "text/xml"
	}
	return &http.Response{
		StatusCode: resp.status,
		Header:     http.Header{"Content-Type": []string{contentType}},
		Body:       io.NopCloser(strings.NewReader(resp.body)),
		Request:    req,
	}, nil
}

// newFakeProvider returns a provider whose configs for regions all route to
// fake, with the account ID pre-resolved so no STS call is made.
func newFakeProvider(fake *fakeAWS, regions ...string) *AWSConfigProvider {
	provider := NewAWSConfigProvider(plugin.AWSCommonRecon{Regions: regions, Concurrency: 2})
	for _, region := range regions {
		cfg := aws.Config{
			Region:      region,
			Credentials: aws.AnonymousCredentials{},
			HTTPClient:  &http.Client{Transport: fake},
			Retryer:     func() aws.Retryer { return aws.NopRetryer{} },
		}
		provider.configs[region] = &cfg
	}
	provider.accountIDOnce.Do(func() { provider.accountID = fakeAccountID })
	return provider
}

func newFakeCloudControl(provider *AWSConfigProvider, skipReport *SkipReport) *CloudControlEnumerator {
	return NewCloudControlEnumeratorWithProvider(provider.AWSCommonRecon, provider, skipReport)
}

// collectFakeResources runs fn against a fresh pipeline and returns what it sent
// together with fn's own error.
func collectFakeResources(t *testing.T, fn func(out *pipeline.P[output.AWSResource]) error) ([]output.AWSResource, error) {
	t.Helper()
	out := pipeline.New[output.AWSResource]()
	var runErr error
	go func() {
		runErr = fn(out)
		out.Close()
	}()
	items, err := out.Collect()
	require.NoError(t, err)
	return items, runErr
}

func byResourceID(resources []output.AWSResource) map[string]output.AWSResource {
	m := make(map[string]output.AWSResource, len(resources))
	for _, r := range resources {
		m[r.ResourceID] = r
	}
	return m
}

// ccDescription renders one CloudControl ResourceDescription; props is the
// Properties JSON document, embedded as the string CloudControl returns.
func ccDescription(identifier, props string) string {
	return fmt.Sprintf(`{"Identifier":%q,"Properties":%q}`, identifier, props)
}

func ccListResources(typeName string, descriptions ...string) string {
	return fmt.Sprintf(`{"TypeName":%q,"ResourceDescriptions":[%s]}`, typeName, strings.Join(descriptions, ","))
}

func ccGetResource(typeName, description string) string {
	return fmt.Sprintf(`{"TypeName":%q,"ResourceDescription":%s}`, typeName, description)
}

func jsonError(code string) string {
	return fmt.Sprintf(`{"__type":%q,"message":"test failure"}`, code)
}

func ec2Error(code string) string {
	return fmt.Sprintf(`<Response><Errors><Error><Code>%s</Code><Message>test failure</Message></Error></Errors><RequestID>req-1</RequestID></Response>`, code)
}

func assertSkipRecorded(t *testing.T, skipReport *SkipReport, service, operation, region, code string) {
	t.Helper()
	snap := skipReport.Snapshot()
	require.Len(t, snap, 1, "expected exactly one skip entry")
	assert.Equal(t, service, snap[0].Service)
	assert.Equal(t, operation, snap[0].Operation)
	assert.Equal(t, region, snap[0].Region)
	assert.Equal(t, code, snap[0].ErrorCode)
}
