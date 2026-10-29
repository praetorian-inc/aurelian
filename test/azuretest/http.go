package azuretest

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

type Credential struct {
	Scopes []string
	Err    error
}

func (c *Credential) GetToken(_ context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	c.Scopes = append(c.Scopes, options.Scopes...)
	if c.Err != nil {
		return azcore.AccessToken{}, c.Err
	}
	return azcore.AccessToken{Token: "offline-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

type TransportFunc func(*http.Request) (*http.Response, error)

func (f TransportFunc) Do(req *http.Request) (*http.Response, error) {
	return f(req)
}

func JSONResponse(req *http.Request, status int, body string) *http.Response {
	return &http.Response{
		Request:    req,
		StatusCode: status,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
