// Package azuretest provides offline Azure request fixtures. It never forwards
// an unmatched request to the network.
package azuretest

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// Collect drains unbuffered pipeline output while the tested operation runs.
func Collect[T any](operation func(*pipeline.P[T]) error) ([]T, error) {
	out := pipeline.New[T]()
	go func() { out.CloseWithError(operation(out)) }()
	return out.Collect()
}

type Transport func(*http.Request) (*http.Response, error)

func (f Transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Install is intentionally not compatible with t.Parallel in the same package.
// Requests within a test may be concurrent; handlers must synchronize state.
func Install(t *testing.T, handler Transport) {
	t.Helper()
	previous := http.DefaultTransport
	http.DefaultTransport = handler
	t.Cleanup(func() { http.DefaultTransport = previous })
}

func JSON(r *http.Request, body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}
}

type Credential struct {
	mu     sync.Mutex
	scopes []string
	Token  string
}

func (c *Credential) GetToken(_ context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.scopes = append(c.scopes, opts.Scopes...)
	return azcore.AccessToken{Token: c.Token, ExpiresOn: time.Now().Add(time.Hour)}, nil
}
func (c *Credential) Scopes() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.scopes...)
}

func NewCredential(t *testing.T, cloudType string) (*Credential, azurecloud.Environment) {
	t.Helper()
	return &Credential{Token: "offline-" + cloudType}, azurecloud.Resolve(cloudType)
}
