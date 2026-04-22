package apim

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// APIListAPIVersion is the minimum ARM api-version required to enumerate
// native MCP-type APIs. Older versions (2021-08-01, 2023-05-01-preview)
// filter MCP APIs out of the list response entirely.
const APIListAPIVersion = "2024-06-01-preview"

// armScope is the Azure Resource Manager scope for bearer tokens.
const armScope = "https://management.azure.com/.default"

type apiListResponse struct {
	Value    []apiListEntry `json:"value"`
	NextLink string         `json:"nextLink,omitempty"`
}

type apiListEntry struct {
	Name       string            `json:"name"`
	Properties apiListProperties `json:"properties"`
}

type apiListProperties struct {
	DisplayName          string   `json:"displayName,omitempty"`
	Path                 string   `json:"path,omitempty"`
	Protocols            []string `json:"protocols,omitempty"`
	SubscriptionRequired bool     `json:"subscriptionRequired,omitempty"`
	Type                 string   `json:"type,omitempty"`
}

// parseAPIListPage parses one page of the ARM `/apis` response body into a
// slice of APIInventoryItem, setting IsMCPServer based on the authoritative
// `properties.type == "mcp"` signal.
func parseAPIListPage(body []byte) ([]APIInventoryItem, string, error) {
	var resp apiListResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, "", fmt.Errorf("unmarshal api list: %w", err)
	}
	if len(resp.Value) == 0 {
		return nil, resp.NextLink, nil
	}
	items := make([]APIInventoryItem, 0, len(resp.Value))
	for _, entry := range resp.Value {
		items = append(items, APIInventoryItem{
			APIID:                entry.Name,
			DisplayName:          entry.Properties.DisplayName,
			Path:                 entry.Properties.Path,
			Protocols:            entry.Properties.Protocols,
			SubscriptionRequired: entry.Properties.SubscriptionRequired,
			IsMCPServer:          strings.EqualFold(entry.Properties.Type, "mcp"),
		})
	}
	return items, resp.NextLink, nil
}

// ListAPIs enumerates every API (including native MCP-type APIs) on the given
// APIM service via ARM's `/apis` endpoint at api-version 2024-06-01-preview.
// The SDK's APIClient.NewListByServicePager pins api-version=2021-08-01, which
// hides MCP-type APIs from the response — so we go directly to ARM here.
//
// Pagination is followed via the response's nextLink. Transient 429/503
// errors are retried via the standard Azure paginator.
func ListAPIs(ctx context.Context, cred azcore.TokenCredential, subscriptionID, resourceGroup, serviceName string) ([]APIInventoryItem, error) {
	base := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ApiManagement/service/%s/apis?api-version=%s",
		url.PathEscape(subscriptionID),
		url.PathEscape(resourceGroup),
		url.PathEscape(serviceName),
		APIListAPIVersion,
	)

	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{armScope}})
	if err != nil {
		return nil, fmt.Errorf("acquire ARM token: %w", err)
	}

	client := http.DefaultClient
	var all []APIInventoryItem
	next := base
	paginator := ratelimit.NewAzurePaginator()

	err = paginator.Paginate(func() (bool, error) {
		if next == "" {
			return false, nil
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, next, nil)
		if err != nil {
			return false, err
		}
		req.Header.Set("Authorization", "Bearer "+token.Token)
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			return true, err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false, err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return false, fmt.Errorf("ARM list APIs returned %d: %s", resp.StatusCode, truncate(string(body), 256))
		}

		page, nextLink, perr := parseAPIListPage(body)
		if perr != nil {
			return false, perr
		}
		all = append(all, page...)
		next = nextLink
		return next != "", nil
	})
	if err != nil {
		return nil, err
	}
	return all, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
