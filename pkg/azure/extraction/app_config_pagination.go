package extraction

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
)

// This SDK version joins App Configuration nextLinks onto the endpoint as a
// path. Validate response links BEFORE that transformation so an absolute link
// to another cloud isn't hidden inside a same-origin request path.
type appConfigPaginationPolicy struct{ endpoint string }

func (p appConfigPaginationPolicy) Do(req *policy.Request) (*http.Response, error) {
	response, err := req.Next()
	if err != nil || response.StatusCode != http.StatusOK {
		return response, err
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 16*1024*1024+1))
	_ = response.Body.Close()
	if err != nil {
		return nil, err
	}
	if len(body) > 16*1024*1024 {
		return nil, fmt.Errorf("App Configuration page exceeds response size limit")
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	var page struct {
		NextLink string `json:"@nextLink"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("invalid App Configuration page")
	}
	if err := p.validateLink(page.NextLink); err != nil {
		return nil, err
	}
	// The SDK also reads the Link header when @nextLink is absent.
	if page.NextLink == "" {
		link := response.Header.Get("Link")
		start, end := strings.Index(link, "<"), strings.Index(link, ">")
		if start >= 0 && end > start {
			if err := p.validateLink(link[start+1 : end]); err != nil {
				return nil, err
			}
		}
	}
	return response, nil
}

func (p appConfigPaginationPolicy) validateLink(raw string) error {
	if raw == "" {
		return nil
	}
	link, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid App Configuration pagination URL")
	}
	if !link.IsAbs() && link.Host == "" {
		origin, _ := url.Parse(p.endpoint)
		link = origin.ResolveReference(link)
	}
	return azurecloud.ValidateURL(link.String(), p.endpoint)
}
