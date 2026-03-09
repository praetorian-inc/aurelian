package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// ---------------------------------------------------------------------------
// MgmtGroupClient interface — the seam for testing
// ---------------------------------------------------------------------------

// MgmtGroupClient abstracts Azure Management Groups API calls so the
// collector can be tested with a mock implementation.
type MgmtGroupClient interface {
	// Get performs a GET request against the given full URL and returns the
	// raw JSON response body.
	Get(ctx context.Context, url string) ([]byte, error)
}

// ---------------------------------------------------------------------------
// azureMgmtGroupClient — production implementation using azcore
// ---------------------------------------------------------------------------

const mgmtBaseURL = "https://management.azure.com"

type azureMgmtGroupClient struct {
	cred azcore.TokenCredential
}

func (c *azureMgmtGroupClient) Get(ctx context.Context, url string) ([]byte, error) {
	if !strings.HasPrefix(url, "https://") {
		url = mgmtBaseURL + url
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	token, err := c.cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://management.azure.com/.default"},
	})
	if err != nil {
		return nil, fmt.Errorf("acquiring token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ARM API error %d: %s", resp.StatusCode, truncateMgmt(string(body), 512))
	}
	return body, nil
}

func truncateMgmt(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ---------------------------------------------------------------------------
// API response types for deserialization
// ---------------------------------------------------------------------------

// mgmtGroupListResponse is the envelope for the list management groups endpoint.
type mgmtGroupListResponse struct {
	Value []mgmtGroupListItem `json:"value"`
}

// mgmtGroupListItem represents a single management group in the list response.
type mgmtGroupListItem struct {
	ID         string                   `json:"id"`
	Name       string                   `json:"name"`
	Properties mgmtGroupListProperties  `json:"properties"`
}

type mgmtGroupListProperties struct {
	DisplayName string `json:"displayName"`
	TenantID    string `json:"tenantId"`
}

// mgmtGroupExpandResponse represents the response from the expand endpoint.
type mgmtGroupExpandResponse struct {
	ID         string                     `json:"id"`
	Name       string                     `json:"name"`
	Properties mgmtGroupExpandProperties  `json:"properties"`
}

type mgmtGroupExpandProperties struct {
	DisplayName string                `json:"displayName"`
	TenantID    string                `json:"tenantId"`
	Children    []mgmtGroupChildNode  `json:"children"`
}

// mgmtGroupChildNode represents a child in the hierarchy tree — either a
// management group or a subscription.
type mgmtGroupChildNode struct {
	ID         string                     `json:"id"`
	Name       string                     `json:"name"`
	Type       string                     `json:"type"`
	Properties *mgmtGroupChildProperties  `json:"properties,omitempty"`
	Children   []mgmtGroupChildNode       `json:"children,omitempty"`
}

type mgmtGroupChildProperties struct {
	DisplayName string `json:"displayName"`
}

// ---------------------------------------------------------------------------
// MgmtGroupsCollector
// ---------------------------------------------------------------------------

const (
	mgmtGroupListURL   = "/providers/Microsoft.Management/managementGroups?api-version=2021-04-01"
	mgmtGroupExpandFmt = "/providers/Microsoft.Management/managementGroups/%s?$expand=children&$recurse=true&api-version=2021-04-01"
)

// MgmtGroupsCollector collects Azure management group hierarchy data.
type MgmtGroupsCollector struct {
	client     MgmtGroupClient
	batchDelay time.Duration
}

// NewMgmtGroupsCollector creates a collector that authenticates with the
// given Azure credential.
func NewMgmtGroupsCollector(cred azcore.TokenCredential) *MgmtGroupsCollector {
	return &MgmtGroupsCollector{
		client:     &azureMgmtGroupClient{cred: cred},
		batchDelay: 200 * time.Millisecond,
	}
}

// newMgmtGroupsCollectorWithClient creates a collector with a custom
// MgmtGroupClient. This is the primary constructor used by tests.
func newMgmtGroupsCollectorWithClient(client MgmtGroupClient) *MgmtGroupsCollector {
	return &MgmtGroupsCollector{
		client:     client,
		batchDelay: 0,
	}
}

// Collect gathers management group hierarchy data. Individual API failures
// are logged but non-fatal — the collector returns as much data as possible.
func (c *MgmtGroupsCollector) Collect(ctx context.Context) (*types.ManagementGroupData, error) {
	data := &types.ManagementGroupData{}

	// 1. List all management groups.
	listBody, err := c.client.Get(ctx, mgmtGroupListURL)
	if err != nil {
		slog.Warn("failed to list management groups", "error", err)
		return data, nil
	}

	var listResp mgmtGroupListResponse
	if err := json.Unmarshal(listBody, &listResp); err != nil {
		slog.Warn("failed to unmarshal management groups list", "error", err)
		return data, nil
	}

	if len(listResp.Value) == 0 {
		return data, nil
	}

	// Convert list items to typed ManagementGroup entries.
	for _, item := range listResp.Value {
		data.Groups = append(data.Groups, types.ManagementGroup{
			ID:          item.ID,
			DisplayName: item.Properties.DisplayName,
			Name:        item.Name,
			TenantID:    item.Properties.TenantID,
		})
	}

	// 2. Find the root management group. The root group's name matches the
	//    tenant ID, or fall back to the first group.
	rootName := listResp.Value[0].Name
	for _, item := range listResp.Value {
		if item.Name == item.Properties.TenantID {
			rootName = item.Name
			break
		}
	}

	// 3. Fetch root with $expand=children&$recurse=true to get hierarchy.
	expandURL := fmt.Sprintf(mgmtGroupExpandFmt, rootName)
	expandBody, err := c.client.Get(ctx, expandURL)
	if err != nil {
		slog.Warn("failed to expand management group hierarchy", "rootId", rootName, "error", err)
		// Return groups without relationships.
		return data, nil
	}

	var expandResp mgmtGroupExpandResponse
	if err := json.Unmarshal(expandBody, &expandResp); err != nil {
		slog.Warn("failed to unmarshal management group hierarchy", "error", err)
		return data, nil
	}

	// 4. Walk the hierarchy tree to build relationships.
	data.Relationships = walkHierarchy(expandResp.ID, expandResp.Properties.Children)

	return data, nil
}

// walkHierarchy recursively traverses the management group tree and builds
// parent-child relationship entries.
func walkHierarchy(parentID string, children []mgmtGroupChildNode) []types.ManagementGroupRelationship {
	var rels []types.ManagementGroupRelationship

	for _, child := range children {
		childType := classifyChildType(child.Type)

		rels = append(rels, types.ManagementGroupRelationship{
			ParentID:  parentID,
			ChildID:   child.ID,
			ChildType: childType,
		})

		// Recurse into children (only management groups have children).
		if len(child.Children) > 0 {
			rels = append(rels, walkHierarchy(child.ID, child.Children)...)
		}
	}

	return rels
}

// classifyChildType maps the ARM resource type string to a short child type.
func classifyChildType(armType string) string {
	t := strings.ToLower(armType)
	if strings.Contains(t, "subscription") {
		return "subscription"
	}
	return "managementGroup"
}
