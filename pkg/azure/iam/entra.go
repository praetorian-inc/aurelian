// Package iam provides collectors for Azure Entra ID (Azure AD) data.
//
// The EntraCollector gathers 15 categories of identity data from Microsoft
// Graph API and returns a strongly-typed [types.EntraIDData]. Errors on
// individual collections are logged but non-fatal — the collector always
// returns as much data as it can gather.
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
	cred azcore.TokenCredential
}

func (c *azureGraphClient) Get(ctx context.Context, path string) ([]byte, error) {
	url := path
	if !strings.HasPrefix(path, "https://") {
		url = graphBaseURL + path
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	token, err := c.cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://graph.microsoft.com/.default"},
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
		return nil, fmt.Errorf("Graph API error %d: %s", resp.StatusCode, truncate(string(body), 512))
	}
	return body, nil
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
type EntraCollector struct {
	client GraphClient

	// batchDelay is the delay between batch API calls to avoid rate limiting.
	batchDelay time.Duration
}

// NewEntraCollector creates a collector that authenticates with the given
// Azure credential.
func NewEntraCollector(cred azcore.TokenCredential) *EntraCollector {
	return &EntraCollector{
		client:     &azureGraphClient{cred: cred},
		batchDelay: 200 * time.Millisecond,
	}
}

// newEntraCollectorWithClient creates a collector with a custom GraphClient.
// This is the primary constructor used by tests.
func newEntraCollectorWithClient(client GraphClient) *EntraCollector {
	return &EntraCollector{
		client:     client,
		batchDelay: 0, // no delay in tests
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

// collectGroupMemberships iterates over groups and fetches members for each.
func (c *EntraCollector) collectGroupMemberships(ctx context.Context, groups store.Map[types.EntraGroup]) []types.GroupMembership {
	var all []types.GroupMembership
	groups.Range(func(_ string, g types.EntraGroup) bool {
		members, err := paginate[groupMemberItem](ctx, c.client, "/groups/"+g.ObjectID+"/members")
		if err != nil {
			slog.Warn("failed to collect group members", "groupId", g.ObjectID, "error", err)
			return true // continue
		}
		for _, m := range members {
			all = append(all, types.GroupMembership{
				GroupID:    g.ObjectID,
				MemberID:   m.ID,
				MemberType: m.ODataType,
			})
		}
		if c.batchDelay > 0 {
			time.Sleep(c.batchDelay)
		}
		return true
	})
	return all
}

type groupMemberItem struct {
	ID        string `json:"id"`
	ODataType string `json:"@odata.type"`
}

// collectAppRoleAssignments iterates over service principals and fetches
// app role assignments for each.
func (c *EntraCollector) collectAppRoleAssignments(ctx context.Context, sps store.Map[types.EntraServicePrincipal]) []types.AppRoleAssignment {
	var all []types.AppRoleAssignment
	sps.Range(func(_ string, sp types.EntraServicePrincipal) bool {
		assignments, err := paginate[types.AppRoleAssignment](ctx, c.client, "/servicePrincipals/"+sp.ObjectID+"/appRoleAssignments")
		if err != nil {
			slog.Warn("failed to collect app role assignments", "spId", sp.ObjectID, "error", err)
			return true
		}
		all = append(all, assignments...)
		if c.batchDelay > 0 {
			time.Sleep(c.batchDelay)
		}
		return true
	})
	return all
}

// collectOwnershipsByIDs fetches owners for a list of entity IDs via the
// Graph API and returns ownership relationships.
func (c *EntraCollector) collectOwnershipsByIDs(
	ctx context.Context,
	entityIDs []string,
	resourceType string,
	basePath string,
) []types.OwnershipRelationship {
	var all []types.OwnershipRelationship

	for _, entityID := range entityIDs {
		owners, err := paginate[graphDirectoryObject](ctx, c.client, basePath+entityID+"/owners")
		if err != nil {
			slog.Warn("failed to collect owners", "resourceType", resourceType, "resourceId", entityID, "error", err)
			continue
		}
		for _, owner := range owners {
			all = append(all, types.OwnershipRelationship{
				OwnerID:      owner.ID,
				ResourceID:   entityID,
				ResourceType: resourceType,
			})
		}
		if c.batchDelay > 0 {
			time.Sleep(c.batchDelay)
		}
	}

	return all
}
