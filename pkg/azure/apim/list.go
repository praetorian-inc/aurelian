package apim

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"

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
	return apiListResponseToItems(resp), resp.NextLink, nil
}

// ListAPIs enumerates every API (including native MCP-type APIs) on the given
// APIM service via ARM's `/apis` endpoint at api-version 2024-06-01-preview.
// The SDK's APIClient.NewListByServicePager pins api-version=2021-08-01, which
// hides MCP-type APIs from the response — so we go directly to ARM here.
//
// Pagination is followed via the response's nextLink, but only when nextLink's
// host matches the original ARM endpoint — never send the bearer token to a
// foreign host. Transient 429/503 errors surface as *azcore.ResponseError so
// the standard Azure paginator retries them.
func ListAPIs(ctx context.Context, cred azcore.TokenCredential, subscriptionID, resourceGroup, serviceName string) ([]APIInventoryItem, error) {
	base := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ApiManagement/service/%s/apis?api-version=%s",
		url.PathEscape(subscriptionID),
		url.PathEscape(resourceGroup),
		url.PathEscape(serviceName),
		APIListAPIVersion,
	)
	baseURL, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("parse base URL: %w", err)
	}

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
		if err := validateARMURL(next, baseURL); err != nil {
			// Refuse to attach the bearer token to an unexpected host. Not
			// retryable — this is a structural failure, not a transient one.
			return false, err
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
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			// Surface as *azcore.ResponseError so paginator's retry decision
			// (which only matches that type) handles 429/503 correctly. The
			// runtime helper consumes resp.Body on our behalf.
			return false, runtime.NewResponseError(resp)
		}
		defer resp.Body.Close()

		page, nextLink, perr := parsePager(resp)
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

// validateARMURL refuses any URL that isn't HTTPS or whose host doesn't match
// the ARM base host. ARM nextLinks must point back at the same host that
// served the first page; anything else is either a misconfigured response
// or a redirection attempt and we will not attach the bearer token to it.
func validateARMURL(raw string, base *url.URL) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse pagination URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("refusing non-HTTPS pagination URL: %s", redactURL(u))
	}
	if !strings.EqualFold(u.Host, base.Host) {
		return fmt.Errorf("refusing pagination URL with foreign host %q (expected %q)", u.Host, base.Host)
	}
	return nil
}

// redactURL returns a string form of u with the query string omitted. ARM
// nextLink query strings include continuation tokens we shouldn't echo.
func redactURL(u *url.URL) string {
	cp := *u
	cp.RawQuery = ""
	return cp.String()
}

// parsePager reads the response body into an apiListResponse via the existing
// page-parsing path.
func parsePager(resp *http.Response) ([]APIInventoryItem, string, error) {
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	var listResp apiListResponse
	if err := dec.Decode(&listResp); err != nil {
		return nil, "", fmt.Errorf("decode api list: %w", err)
	}
	return apiListResponseToItems(listResp), listResp.NextLink, nil
}

func apiListResponseToItems(resp apiListResponse) []APIInventoryItem {
	if len(resp.Value) == 0 {
		return nil
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
	return items
}
