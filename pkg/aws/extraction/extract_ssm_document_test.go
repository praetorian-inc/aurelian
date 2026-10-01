package extraction

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const ssmTestDocARN = "arn:aws:ssm:us-east-1:123456789012:document/deploy"

// fakeSSMDocumentTransport routes SSM JSON requests by X-Amz-Target operation
// and records every request body per operation.
type fakeSSMDocumentTransport struct {
	t        *testing.T
	mu       sync.Mutex
	handlers map[string]func(input map[string]any) (int, string)
	calls    map[string][]map[string]any
}

func newFakeSSMDocumentTransport(t *testing.T) *fakeSSMDocumentTransport {
	return &fakeSSMDocumentTransport{
		t:        t,
		handlers: map[string]func(map[string]any) (int, string){},
		calls:    map[string][]map[string]any{},
	}
}

func (f *fakeSSMDocumentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(req.Body)
	_, op, _ := strings.Cut(req.Header.Get("X-Amz-Target"), ".")
	var input map[string]any
	_ = json.Unmarshal(body, &input)

	f.mu.Lock()
	f.calls[op] = append(f.calls[op], input)
	h, ok := f.handlers[op]
	f.mu.Unlock()

	status, resp := http.StatusBadRequest, `{"__type":"UnexpectedCall"}`
	if ok {
		status, resp = h(input)
	} else {
		assert.Fail(f.t, "unexpected AWS call", "operation %q", op)
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/x-amz-json-1.1"}},
		Body:       io.NopCloser(strings.NewReader(resp)),
		Request:    req,
	}, nil
}

func (f *fakeSSMDocumentTransport) requests(op string) []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.calls[op]...)
}

// listVersionsInTwoPages answers ListDocumentVersions with versions 1 and 2 on
// the first page and version 3 on the second.
func (f *fakeSSMDocumentTransport) listVersionsInTwoPages() {
	f.handlers["ListDocumentVersions"] = func(input map[string]any) (int, string) {
		if input["NextToken"] == "page-2" {
			return http.StatusOK, `{"DocumentVersions":[{"Name":"deploy","DocumentVersion":"3"}]}`
		}
		return http.StatusOK, `{"DocumentVersions":[{"Name":"deploy","DocumentVersion":"1"},{"Name":"deploy","DocumentVersion":"2"}],"NextToken":"page-2"}`
	}
}

// getDocumentContent answers GetDocument with content per requested version;
// a version mapped to "" gets empty Content, an absent one an AccessDenied.
func (f *fakeSSMDocumentTransport) getDocumentContent(byVersion map[string]string) {
	f.handlers["GetDocument"] = func(input map[string]any) (int, string) {
		version, _ := input["DocumentVersion"].(string)
		content, ok := byVersion[version]
		if !ok {
			return http.StatusBadRequest, `{"__type":"AccessDeniedException","message":"denied"}`
		}
		b, _ := json.Marshal(map[string]any{"Name": "deploy", "DocumentVersion": version, "Content": content})
		return http.StatusOK, string(b)
	}
}

func runExtractSSMDocument(t *testing.T, fake *fakeSSMDocumentTransport) ([]output.ScanInput, error) {
	t.Helper()
	ctx := extractContext{
		Context: context.Background(),
		AWSConfig: aws.Config{
			Region:      "us-east-1",
			Credentials: aws.AnonymousCredentials{},
			HTTPClient:  &http.Client{Transport: fake},
			Retryer:     func() aws.Retryer { return aws.NopRetryer{} },
		},
	}
	r := output.AWSResource{
		ResourceType: "AWS::SSM::Document",
		ResourceID:   "deploy",
		ARN:          ssmTestDocARN,
		AccountRef:   "123456789012",
		Region:       "us-east-1",
		Properties:   map[string]any{"Name": "deploy", "DocumentVersion": "1"},
	}

	out := pipeline.New[output.ScanInput]()
	var extractErr error
	go func() {
		extractErr = extractSSM(ctx, r, out)
		out.Close()
	}()
	items, err := out.Collect()
	require.NoError(t, err)
	return items, extractErr
}

func byScanResourceID(items []output.ScanInput) map[string]output.ScanInput {
	m := make(map[string]output.ScanInput, len(items))
	for _, in := range items {
		m[in.ResourceID] = in
	}
	return m
}

func TestExtractSSM_ScansEveryVersionAcrossPages(t *testing.T) {
	fake := newFakeSSMDocumentTransport(t)
	fake.listVersionsInTwoPages()
	fake.getDocumentContent(map[string]string{"1": "content-v1", "2": "content-v2", "3": "content-v3"})

	items, err := runExtractSSMDocument(t, fake)

	require.NoError(t, err)
	require.Len(t, items, 3)
	got := byScanResourceID(items)
	for _, v := range []string{"1", "2", "3"} {
		in, ok := got[ssmTestDocARN+":"+v]
		require.True(t, ok, "missing ScanInput for version %s; got %v", v, items)
		assert.Equal(t, "Document version "+v, in.Label)
		assert.Equal(t, []byte("content-v"+v), in.Content)
		assert.Equal(t, "AWS::SSM::Document", in.ResourceType)
	}

	var requested []string
	for _, req := range fake.requests("GetDocument") {
		assert.Equal(t, "deploy", req["Name"])
		requested = append(requested, fmt.Sprint(req["DocumentVersion"]))
	}
	assert.ElementsMatch(t, []string{"1", "2", "3"}, requested, "each GetDocument names its version")

	listReqs := fake.requests("ListDocumentVersions")
	require.Len(t, listReqs, 2, "both ListDocumentVersions pages are fetched")
	assert.Equal(t, "deploy", listReqs[0]["Name"])
}

func TestExtractSSM_FailedVersionIsSkippedOthersEmitted(t *testing.T) {
	fake := newFakeSSMDocumentTransport(t)
	fake.listVersionsInTwoPages()
	fake.getDocumentContent(map[string]string{"1": "content-v1", "3": "content-v3"}) // version 2 denied

	items, err := runExtractSSMDocument(t, fake)

	require.NoError(t, err, "one unreadable version must not fail the document")
	got := byScanResourceID(items)
	assert.Len(t, items, 2)
	assert.Contains(t, got, ssmTestDocARN+":1")
	assert.Contains(t, got, ssmTestDocARN+":3")
	assert.NotContains(t, got, ssmTestDocARN+":2")
	assert.Len(t, fake.requests("GetDocument"), 3, "version 3 is still fetched after version 2 fails")
}

func TestExtractSSM_ListDocumentVersionsFailureReturnsError(t *testing.T) {
	fake := newFakeSSMDocumentTransport(t)
	fake.handlers["ListDocumentVersions"] = func(map[string]any) (int, string) {
		return http.StatusBadRequest, `{"__type":"AccessDeniedException","message":"denied"}`
	}

	items, err := runExtractSSMDocument(t, fake)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "ListDocumentVersions")
	assert.Empty(t, items)
	assert.Empty(t, fake.requests("GetDocument"))
}

func TestExtractSSM_EmptyContentVersionSkipped(t *testing.T) {
	fake := newFakeSSMDocumentTransport(t)
	fake.listVersionsInTwoPages()
	fake.getDocumentContent(map[string]string{"1": "content-v1", "2": "", "3": "content-v3"})

	items, err := runExtractSSMDocument(t, fake)

	require.NoError(t, err)
	got := byScanResourceID(items)
	assert.Len(t, items, 2)
	assert.NotContains(t, got, ssmTestDocARN+":2", "empty-content version produces no ScanInput")
	assert.Contains(t, got, ssmTestDocARN+":1")
	assert.Contains(t, got, ssmTestDocARN+":3")
}
