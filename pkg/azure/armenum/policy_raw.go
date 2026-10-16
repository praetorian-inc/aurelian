package armenum

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/praetorian-inc/aurelian/pkg/azure/azurecloud"
)

// rawPolicyPager pages through Azure policy definitions using raw HTTP + JSON
// to avoid SDK unmarshalling crashes caused by metadata type mismatches
// (e.g., "assignPermissions": "true" instead of true in custom policies).
type rawPolicyPager struct {
	cred    azcore.TokenCredential
	client  *http.Client
	nextURL string
}

// rawPolicyDef holds the minimal fields we need from a policy definition.
// Unmarshalled with standard json which tolerates extra/mistyped fields in
// nested objects since we only extract top-level strings.
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

func newRawPolicyPager(subscriptionID string, cred azcore.TokenCredential) (*rawPolicyPager, error) {
	if cred == nil {
		return nil, fmt.Errorf("credential is nil")
	}
	return &rawPolicyPager{
		cred:    cred,
		client:  azurecloud.HTTPClient(30 * time.Second),
		nextURL: fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Authorization/policyDefinitions?api-version=2023-04-01", azurecloud.ForCredential(cred).ARM, subscriptionID),
	}, nil
}

func (p *rawPolicyPager) nextPage(ctx context.Context) (defs []rawPolicyDef, nextLink string, err error) {
	if p.nextURL == "" {
		return nil, "", nil
	}

	environment := azurecloud.ForCredential(p.cred)
	if err := azurecloud.ValidateURL(p.nextURL, environment.ARM); err != nil {
		return nil, "", err
	}
	token, err := p.cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{environment.ARMScope},
	})
	if err != nil {
		return nil, "", fmt.Errorf("acquiring token: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", p.nextURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.Token)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("HTTP request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body[:min(500, len(body))]))
	}

	// Unmarshal the page envelope with raw messages per definition.
	var page rawPolicyPage
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, "", fmt.Errorf("unmarshalling page envelope: %w", err)
	}

	// Unmarshal each definition individually — skip malformed ones instead of
	// crashing the entire page.
	for _, raw := range page.Value {
		var def rawPolicyDef
		if err := json.Unmarshal(raw, &def); err != nil {
			// Individual definition is malformed — log and skip, don't crash.
			continue
		}
		defs = append(defs, def)
	}

	// Validate nextLink stays within Azure management plane to prevent SSRF.
	if page.NextLink != "" {
		if err := azurecloud.ValidateURL(page.NextLink, environment.ARM); err != nil {
			return nil, "", err
		}
	}
	p.nextURL = page.NextLink
	return defs, page.NextLink, nil
}
