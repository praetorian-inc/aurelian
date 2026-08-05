// Package iam provides collectors for Azure Entra ID (Azure AD) data.
//
// The EntraCollector gathers 15 categories of identity data from Microsoft
// Graph API and returns a strongly-typed [types.EntraIDData]. Errors on
// individual collections are logged but non-fatal — the collector always
// returns as much data as it can gather.
package iam

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/praetorian-inc/aurelian/pkg/store"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// ---------------------------------------------------------------------------
// GraphClient interface — the seam for testing
// ---------------------------------------------------------------------------

// GraphClient abstracts Microsoft Graph REST API calls so the collector
// can be tested with a mock implementation.
type GraphClient interface {
	// Get performs a GET request against the given Graph API path (e.g.
	// "/users") and returns the raw JSON response body. The path is relative
	// to https://graph.microsoft.com/v1.0.
	Get(ctx context.Context, path string) ([]byte, error)
}

// ---------------------------------------------------------------------------
// graphResponse is the common envelope for Graph API list responses.
// ---------------------------------------------------------------------------

type graphResponse struct {
	Value    json.RawMessage `json:"value"`
	NextLink string          `json:"@odata.nextLink,omitempty"`
}

// ---------------------------------------------------------------------------
// azureGraphClient — production implementation using azcore
// ---------------------------------------------------------------------------

const graphBaseURL = "https://graph.microsoft.com/v1.0"

type azureGraphClient struct {
	cred   azcore.TokenCredential
	client *http.Client
}

var graphHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		// Explicitly disable HTTP/2 — Azure endpoints sometimes stall
		// on HTTP/2 frame reads, causing indefinite hangs.
		TLSNextProto: make(map[string]func(string, *tls.Conn) http.RoundTripper),
	},
}

func (c *azureGraphClient) Get(ctx context.Context, path string) ([]byte, error) {
	return doWithRetry(ctx, c.cred, "https://graph.microsoft.com/.default", c.client, path, graphBaseURL)
}

// ---------------------------------------------------------------------------
// cachedCredential — avoids shelling out to `az` for every API call
// ---------------------------------------------------------------------------

// cachedCredential wraps an azcore.TokenCredential and caches the token
// per scope, only refreshing when the token is within 5 minutes of expiry.
// This is critical for AzureCLICredential which spawns a subprocess per call.
type cachedCredential struct {
	inner  azcore.TokenCredential
	mu     sync.Mutex
	tokens map[string]azcore.AccessToken
}

func newCachedCredential(cred azcore.TokenCredential) *cachedCredential {
	return &cachedCredential{
		inner:  cred,
		tokens: make(map[string]azcore.AccessToken),
	}
}

func (c *cachedCredential) GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	key := strings.Join(opts.Scopes, ",")

	c.mu.Lock()
	if tok, ok := c.tokens[key]; ok {
		// Reuse if token won't expire for at least 5 minutes.
		if time.Until(tok.ExpiresOn) > 5*time.Minute {
			c.mu.Unlock()
			return tok, nil
		}
	}
	c.mu.Unlock()

	// Fetch a fresh token.
	tok, err := c.inner.GetToken(ctx, opts)
	if err != nil {
		return azcore.AccessToken{}, err
	}

	c.mu.Lock()
	c.tokens[key] = tok
	c.mu.Unlock()

	return tok, nil
}

// doWithRetry executes an HTTP GET with automatic retry on 429 (throttling).
// It respects the Retry-After header from Azure APIs.
func doWithRetry(ctx context.Context, cred azcore.TokenCredential, scope string, client *http.Client, path, baseURL string) ([]byte, error) {
	url := path
	if !strings.HasPrefix(path, "https://") {
		url = baseURL + path
	}

	httpClient := client
	if httpClient == nil {
		httpClient = graphHTTPClient
	}

	const maxRetries = 3
	for attempt := 0; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}

		tokenCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		token, err := cred.GetToken(tokenCtx, policy.TokenRequestOptions{
			Scopes: []string{scope},
		})
		cancel()
		if err != nil {
			return nil, fmt.Errorf("acquiring token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token.Token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("HTTP request: %w", err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("reading response: %w", err)
		}

		if resp.StatusCode == http.StatusTooManyRequests && attempt < maxRetries {
			wait := retryAfterDuration(resp.Header)
			slog.Warn("throttled by API, backing off", "attempt", attempt+1, "wait", wait, "url", truncate(url, 80))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
				continue
			}
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			apiName := "API"
			if strings.Contains(baseURL, "graph") {
				apiName = "Graph API"
			} else {
				apiName = "ARM API"
			}
			return nil, fmt.Errorf("%s error %d: %s", apiName, resp.StatusCode, truncate(string(body), 512))
		}
		return body, nil
	}
	return nil, fmt.Errorf("exhausted retries for %s", truncate(url, 80))
}

// doWithRetryPost is like doWithRetry but for POST requests.
func doWithRetryPost(ctx context.Context, cred azcore.TokenCredential, scope string, client *http.Client, path, baseURL string, reqBody []byte) ([]byte, error) {
	url := path
	if !strings.HasPrefix(path, "https://") {
		url = baseURL + path
	}

	httpClient := client
	if httpClient == nil {
		httpClient = graphHTTPClient
	}

	const maxRetries = 3
	for attempt := 0; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
		if err != nil {
			return nil, fmt.Errorf("creating request: %w", err)
		}

		tokenCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		token, err := cred.GetToken(tokenCtx, policy.TokenRequestOptions{
			Scopes: []string{scope},
		})
		cancel()
		if err != nil {
			return nil, fmt.Errorf("acquiring token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token.Token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("HTTP request: %w", err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("reading response: %w", err)
		}

		if resp.StatusCode == http.StatusTooManyRequests && attempt < maxRetries {
			wait := retryAfterDuration(resp.Header)
			slog.Warn("throttled by API, backing off", "attempt", attempt+1, "wait", wait, "url", truncate(url, 80))
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
				continue
			}
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			apiName := "ARM API"
			return nil, fmt.Errorf("%s error %d: %s", apiName, resp.StatusCode, truncate(string(body), 512))
		}
		return body, nil
	}
	return nil, fmt.Errorf("exhausted retries for %s", truncate(url, 80))
}

// retryAfterDuration parses the Retry-After header, falling back to
// exponential backoff if not present.
func retryAfterDuration(h http.Header) time.Duration {
	if ra := h.Get("Retry-After"); ra != "" {
		if secs, err := strconv.Atoi(ra); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	// Default: 5 seconds if no Retry-After header.
	return 5 * time.Second
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ---------------------------------------------------------------------------
// EntraCollector
// ---------------------------------------------------------------------------

// EntraCollector collects Entra ID (Azure AD) identity data from Microsoft
// Graph. It is safe for sequential use; create a new instance per collection.
// Rate limiting is handled adaptively via 429 retry logic in the HTTP client,
// not by fixed delays.
type EntraCollector struct {
	client GraphClient
}

// NewEntraCollector creates a collector that authenticates with the given
// Azure credential.
func NewEntraCollector(cred azcore.TokenCredential) *EntraCollector {
	return &EntraCollector{
		client: &azureGraphClient{cred: newCachedCredential(cred)},
	}
}

// newEntraCollectorWithClient creates a collector with a custom GraphClient.
// This is the primary constructor used by tests.
func newEntraCollectorWithClient(client GraphClient) *EntraCollector {
	return &EntraCollector{
		client: client,
	}
}

// Collect gathers all 15 Entra ID collections and returns the consolidated
// result. Individual collection failures are logged but do not fail the
// overall operation.
func (c *EntraCollector) Collect(ctx context.Context) (*types.EntraIDData, error) {
	tenantID, err := c.getTenantID(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolving tenant ID: %w", err)
	}

	data := &types.EntraIDData{
		TenantID:          tenantID,
		Users:             store.NewMap[types.EntraUser](),
		Groups:            store.NewMap[types.EntraGroup](),
		ServicePrincipals: store.NewMap[types.EntraServicePrincipal](),
		Applications:      store.NewMap[types.EntraApplication](),
	}

	// 1. Users
	users, err := paginate[types.EntraUser](ctx, c.client, "/users")
	if err != nil {
		slog.Warn("failed to collect users", "error", err)
	} else {
		for _, u := range users {
			data.Users.Set(u.ObjectID, u)
		}
	}

	// 2. Groups
	groups, err := paginate[types.EntraGroup](ctx, c.client, "/groups")
	if err != nil {
		slog.Warn("failed to collect groups", "error", err)
	} else {
		for _, g := range groups {
			data.Groups.Set(g.ObjectID, g)
		}
	}

	// 3. Service Principals
	sps, err := paginate[types.EntraServicePrincipal](ctx, c.client, "/servicePrincipals")
	if err != nil {
		slog.Warn("failed to collect service principals", "error", err)
	} else {
		for _, sp := range sps {
			data.ServicePrincipals.Set(sp.ObjectID, sp)
		}
	}

	// 4. Applications (with $expand=owners for ownership + credential enrichment)
	apps, err := paginate[entraApplicationWithOwners](ctx, c.client, "/applications?$expand=owners")
	if err != nil {
		slog.Warn("failed to collect applications", "error", err)
	} else {
		var appOwnerships []types.OwnershipRelationship
		for _, app := range apps {
			creds := app.toCredentials()
			if len(creds) == 0 {
				creds = app.Credentials // fallback to pre-mapped credentials field
			}
			typedApp := types.EntraApplication{
				ObjectID:       app.ObjectID,
				DisplayName:    app.DisplayName,
				AppID:          app.AppID,
				SignInAudience: app.SignInAudience,
				Credentials:    creds,
			}
			data.Applications.Set(typedApp.ObjectID, typedApp)

			for _, owner := range app.Owners {
				appOwnerships = append(appOwnerships, types.OwnershipRelationship{
					OwnerID:      owner.ID,
					ResourceID:   app.ObjectID,
					ResourceType: "application",
				})
			}
		}
		data.OwnershipRelationships = append(data.OwnershipRelationships, appOwnerships...)
	}

	// 5. Devices
	devices, err := paginate[types.EntraDevice](ctx, c.client, "/devices")
	if err != nil {
		slog.Warn("failed to collect devices", "error", err)
	} else {
		data.Devices = devices
	}

	// 6. Directory Roles
	dirRoles, err := paginate[types.DirectoryRole](ctx, c.client, "/directoryRoles")
	if err != nil {
		slog.Warn("failed to collect directory roles", "error", err)
	} else {
		data.DirectoryRoles = dirRoles
	}

	// 7. Role Definitions
	roleDefs, err := paginate[types.EntraRoleDefinition](ctx, c.client, "/roleManagement/directory/roleDefinitions")
	if err != nil {
		slog.Warn("failed to collect role definitions", "error", err)
	} else {
		data.RoleDefinitions = roleDefs
	}

	// 8. Conditional Access Policies
	caps, err := paginate[types.ConditionalAccessPolicy](ctx, c.client, "/identity/conditionalAccess/policies")
	if err != nil {
		slog.Warn("failed to collect conditional access policies", "error", err)
	} else {
		data.ConditionalAccessPolicies = caps
	}

	// 9. Directory Role Assignments
	dras, err := paginate[types.DirectoryRoleAssignment](ctx, c.client, "/roleManagement/directory/roleAssignments")
	if err != nil {
		slog.Warn("failed to collect directory role assignments", "error", err)
	} else {
		data.DirectoryRoleAssignments = dras
	}

	// 10. Group Memberships — iterate each group and fetch members
	data.GroupMemberships = c.collectGroupMemberships(ctx, data.Groups)

	// 11. OAuth2 Permission Grants
	grants, err := paginate[types.OAuth2PermissionGrant](ctx, c.client, "/oauth2PermissionGrants")
	if err != nil {
		slog.Warn("failed to collect oauth2 permission grants", "error", err)
	} else {
		data.OAuth2PermissionGrants = grants
	}

	// 12. App Role Assignments — per service principal
	data.AppRoleAssignments = c.collectAppRoleAssignments(ctx, data.ServicePrincipals)

	// 13. Group Ownership — per group
	var groupIDs []string
	data.Groups.Range(func(_ string, g types.EntraGroup) bool {
		groupIDs = append(groupIDs, g.ObjectID)
		return true
	})
	groupOwnerships := c.collectOwnershipsByIDs(ctx, groupIDs, "group", "/groups/")
	data.OwnershipRelationships = append(data.OwnershipRelationships, groupOwnerships...)

	// 14. Service Principal Ownership — per SP
	var spIDs []string
	data.ServicePrincipals.Range(func(_ string, sp types.EntraServicePrincipal) bool {
		spIDs = append(spIDs, sp.ObjectID)
		return true
	})
	spOwnerships := c.collectOwnershipsByIDs(ctx, spIDs, "servicePrincipal", "/servicePrincipals/")
	data.OwnershipRelationships = append(data.OwnershipRelationships, spOwnerships...)

	// 15. Credential enrichment for applications is handled in step 4 via the
	//     $expand query and the raw application response which includes
	//     keyCredentials and passwordCredentials.

	return data, nil
}

// ---------------------------------------------------------------------------
// Pagination helper
// ---------------------------------------------------------------------------

// paginate fetches all pages of a Graph API list endpoint and returns the
// deserialized items. It follows @odata.nextLink until exhausted.
func paginate[T any](ctx context.Context, client GraphClient, path string) ([]T, error) {
	var all []T
	currentPath := path

	for {
		body, err := client.Get(ctx, currentPath)
		if err != nil {
			return all, err
		}

		var resp graphResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return all, fmt.Errorf("unmarshaling response: %w", err)
		}

		if resp.Value != nil {
			var page []T
			if err := json.Unmarshal(resp.Value, &page); err != nil {
				return all, fmt.Errorf("unmarshaling page items: %w", err)
			}
			all = append(all, page...)
		}

		if resp.NextLink == "" {
			break
		}
		currentPath = resp.NextLink
	}

	return all, nil
}

// ---------------------------------------------------------------------------
// Tenant ID resolution
// ---------------------------------------------------------------------------

type orgResponse struct {
	Value []struct {
		ID string `json:"id"`
	} `json:"value"`
}

func (c *EntraCollector) getTenantID(ctx context.Context) (string, error) {
	body, err := c.client.Get(ctx, "/organization")
	if err != nil {
		return "", err
	}
	var resp orgResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("unmarshaling org response: %w", err)
	}
	if len(resp.Value) == 0 {
		return "", fmt.Errorf("no organization found")
	}
	return resp.Value[0].ID, nil
}

// ---------------------------------------------------------------------------
// Per-entity collection helpers
// ---------------------------------------------------------------------------

// entraApplicationWithOwners is a transient type used during collection to
// capture the $expand=owners response alongside the application fields.
type entraApplicationWithOwners struct {
	ObjectID       string                `json:"id"`
	DisplayName    string                `json:"displayName"`
	AppID          string                `json:"appId"`
	SignInAudience string                `json:"signInAudience,omitempty"`
	Credentials    []types.CredentialInfo `json:"credentials,omitempty"`
	Owners         []graphDirectoryObject `json:"owners,omitempty"`

	// Credential fields from Graph API (not the typed CredentialInfo).
	KeyCredentials      []graphCredential `json:"keyCredentials,omitempty"`
	PasswordCredentials []graphCredential `json:"passwordCredentials,omitempty"`
}

type graphDirectoryObject struct {
	ID string `json:"id"`
}

type graphCredential struct {
	KeyID         string `json:"keyId"`
	DisplayName   string `json:"displayName,omitempty"`
	StartDateTime string `json:"startDateTime,omitempty"`
	EndDateTime   string `json:"endDateTime,omitempty"`
}

// toCredentials converts raw Graph credential responses into typed CredentialInfo.
func (a *entraApplicationWithOwners) toCredentials() []types.CredentialInfo {
	var creds []types.CredentialInfo
	for _, kc := range a.KeyCredentials {
		creds = append(creds, types.CredentialInfo{
			KeyID:         kc.KeyID,
			DisplayName:   kc.DisplayName,
			Type:          "certificate",
			StartDateTime: kc.StartDateTime,
			EndDateTime:   kc.EndDateTime,
		})
	}
	for _, pc := range a.PasswordCredentials {
		creds = append(creds, types.CredentialInfo{
			KeyID:         pc.KeyID,
			DisplayName:   pc.DisplayName,
			Type:          "password",
			StartDateTime: pc.StartDateTime,
			EndDateTime:   pc.EndDateTime,
		})
	}
	return creds
}

// collectGroupMemberships iterates over groups and fetches members for each,
// using up to 10 concurrent goroutines.
func (c *EntraCollector) collectGroupMemberships(ctx context.Context, groups store.Map[types.EntraGroup]) []types.GroupMembership {
	var groupIDs []string
	groups.Range(func(_ string, g types.EntraGroup) bool {
		groupIDs = append(groupIDs, g.ObjectID)
		return true
	})

	type result struct {
		memberships []types.GroupMembership
	}

	results := make([]result, len(groupIDs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for i, gid := range groupIDs {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, groupID string) {
			defer wg.Done()
			defer func() { <-sem }()

			members, err := paginate[groupMemberItem](ctx, c.client, "/groups/"+groupID+"/members")
			if err != nil {
				slog.Warn("failed to collect group members", "groupId", groupID, "error", err)
				return
			}
			var memberships []types.GroupMembership
			for _, m := range members {
				memberships = append(memberships, types.GroupMembership{
					GroupID:    groupID,
					MemberID:   m.ID,
					MemberType: m.ODataType,
				})
			}
			results[idx] = result{memberships: memberships}
		}(i, gid)
	}
	wg.Wait()

	var all []types.GroupMembership
	for _, r := range results {
		all = append(all, r.memberships...)
	}
	return all
}

type groupMemberItem struct {
	ID        string `json:"id"`
	ODataType string `json:"@odata.type"`
}

// collectAppRoleAssignments iterates over service principals and fetches
// app role assignments for each, using up to 10 concurrent goroutines.
func (c *EntraCollector) collectAppRoleAssignments(ctx context.Context, sps store.Map[types.EntraServicePrincipal]) []types.AppRoleAssignment {
	var spIDs []string
	sps.Range(func(_ string, sp types.EntraServicePrincipal) bool {
		spIDs = append(spIDs, sp.ObjectID)
		return true
	})

	results := make([][]types.AppRoleAssignment, len(spIDs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for i, spID := range spIDs {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, id string) {
			defer wg.Done()
			defer func() { <-sem }()

			assignments, err := paginate[types.AppRoleAssignment](ctx, c.client, "/servicePrincipals/"+id+"/appRoleAssignments")
			if err != nil {
				slog.Warn("failed to collect app role assignments", "spId", id, "error", err)
				return
			}
			results[idx] = assignments
		}(i, spID)
	}
	wg.Wait()

	var all []types.AppRoleAssignment
	for _, r := range results {
		all = append(all, r...)
	}
	return all
}

// collectOwnershipsByIDs fetches owners for a list of entity IDs via the
// Graph API and returns ownership relationships, using up to 10 concurrent goroutines.
func (c *EntraCollector) collectOwnershipsByIDs(
	ctx context.Context,
	entityIDs []string,
	resourceType string,
	basePath string,
) []types.OwnershipRelationship {
	results := make([][]types.OwnershipRelationship, len(entityIDs))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for i, entityID := range entityIDs {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, eid string) {
			defer wg.Done()
			defer func() { <-sem }()

			owners, err := paginate[graphDirectoryObject](ctx, c.client, basePath+eid+"/owners")
			if err != nil {
				slog.Warn("failed to collect owners", "resourceType", resourceType, "resourceId", eid, "error", err)
				return
			}
			var ownerships []types.OwnershipRelationship
			for _, owner := range owners {
				ownerships = append(ownerships, types.OwnershipRelationship{
					OwnerID:      owner.ID,
					ResourceID:   eid,
					ResourceType: resourceType,
				})
			}
			results[idx] = ownerships
		}(i, entityID)
	}
	wg.Wait()

	var all []types.OwnershipRelationship
	for _, r := range results {
		all = append(all, r...)
	}
	return all
}
