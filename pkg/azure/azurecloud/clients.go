package azurecloud

import (
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// ARMClientOptions applies the official SDK endpoint AND audience. In Government
// the ARM request hostname is not the token audience.
func ARMClientOptions(cred azcore.TokenCredential) *arm.ClientOptions {
	environment := ForCredential(cred)
	options := ClientOptions(environment.ARM)
	options.Cloud = environment.Cloud
	return &arm.ClientOptions{ClientOptions: options}
}

// ClientOptions pins SDK requests (including nextLinks) to a validated service
// origin, and prevents net/http from bypassing that boundary via redirects.
// additionalOrigins must be individually validated service-returned endpoints,
// never a suffix allowlist. Cosmos regional discovery uses this exact set.
func ClientOptions(origin string, additionalOrigins ...string) azcore.ClientOptions {
	origins := append([]string{origin}, additionalOrigins...)
	return azcore.ClientOptions{
		PerCallPolicies: []policy.Policy{originPolicy{origins: origins}},
		Transport:       &originTransport{origins: origins, client: HTTPClient(30 * time.Second)},
	}
}

func validateOrigins(raw string, origins []string) error {
	var err error
	for _, origin := range origins {
		if err = ValidateURL(raw, origin); err == nil {
			return nil
		}
	}
	return err
}

type originPolicy struct{ origins []string }

func (p originPolicy) Do(req *policy.Request) (*http.Response, error) {
	if err := validateOrigins(req.Raw().URL.String(), p.origins); err != nil {
		return nil, err
	}
	return req.Next()
}

type originTransport struct {
	origins []string
	client  *http.Client
}

func (t *originTransport) Do(req *http.Request) (*http.Response, error) {
	if err := validateOrigins(req.URL.String(), t.origins); err != nil {
		return nil, err
	}
	return t.client.Do(req)
}

// HTTPClient refuses all redirects, including same-domain subdomains to which
// net/http would otherwise forward Authorization. Callers validate nextLinks.
func HTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: http.DefaultTransport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
}
