package armenum

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
)

func newPolicyDefinitionsPager(subscriptionID string, cred azcore.TokenCredential, options *arm.ClientOptions) (*runtime.Pager[armpolicy.DefinitionsClientListResponse], error) {
	if cred == nil {
		return nil, fmt.Errorf("credential is nil")
	}
	options.DisableRPRegistration = true
	options.Retry.MaxRetries = -1
	options.Retry.TryTimeout = 30 * time.Second
	options.PerCallPolicies = append(options.PerCallPolicies, policyListProjection{})
	client, err := armpolicy.NewDefinitionsClient(subscriptionID, cred, options)
	if err != nil {
		return nil, err
	}
	return client.NewListPager(nil), nil
}

// Keep only enumeration fields: even current SDKs reject mistyped parameter metadata.
// Malformed individual definitions are skipped, not allowed to fail the entire page.
type policyListProjection struct{}

func (policyListProjection) Do(req *policy.Request) (*http.Response, error) {
	resp, err := req.Next()
	if err != nil || resp.StatusCode != http.StatusOK {
		return resp, err
	}

	body, err := runtime.Payload(resp)
	if err != nil {
		return resp, err
	}
	var page rawPolicyPage
	if err := json.Unmarshal(body, &page); err != nil {
		return resp, fmt.Errorf("unmarshalling page envelope: %w", err)
	}
	if page.NextLink != "" {
		if err := azurecloud.ValidateARMURL(page.NextLink, req.Raw().URL); err != nil {
			return resp, err
		}
	}

	definitions := page.Value[:0]
	for _, raw := range page.Value {
		var def rawPolicyDef
		if err := json.Unmarshal(raw, &def); err != nil {
			continue
		}
		data, _ := json.Marshal(def)
		definitions = append(definitions, data)
	}
	page.Value = definitions
	body, _ = json.Marshal(page)
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	return resp, nil
}

type rawPolicyDef struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Properties struct {
		PolicyType  string `json:"policyType"`
		DisplayName string `json:"displayName"`
	} `json:"properties"`
}

type rawPolicyPage struct {
	Value    []json.RawMessage `json:"value"`
	NextLink string            `json:"nextLink"`
}
