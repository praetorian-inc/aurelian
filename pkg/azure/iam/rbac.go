package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/praetorian-inc/aurelian/pkg/store"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// ---------------------------------------------------------------------------
// ARMClient interface — the seam for testing
// ---------------------------------------------------------------------------

// ARMClient abstracts Azure ARM REST API calls so the collector can be
// tested with a mock implementation.
type ARMClient interface {
	// Get performs a GET request against the given ARM API path and returns
	// the raw JSON response body. The path is relative to
	// https://management.azure.com unless it starts with "https://".
	Get(ctx context.Context, path string) ([]byte, error)

	// Post performs a POST request against the given ARM API path with the
	// provided request body and returns the raw JSON response body.
	Post(ctx context.Context, path string, body []byte) ([]byte, error)
}

// ---------------------------------------------------------------------------
// armListResponse is the common envelope for ARM API list responses.
// ---------------------------------------------------------------------------

type armListResponse struct {
	Value    json.RawMessage `json:"value"`
	NextLink string          `json:"nextLink,omitempty"`
}

// ---------------------------------------------------------------------------
// azureARMClient — production implementation using azcore
// ---------------------------------------------------------------------------

const armBaseURL = "https://management.azure.com"

type azureARMClient struct {
	cred azcore.TokenCredential
}

func (c *azureARMClient) Get(ctx context.Context, path string) ([]byte, error) {
	return doWithRetry(ctx, c.cred, "https://management.azure.com/.default", nil, path, armBaseURL)
}

func (c *azureARMClient) Post(ctx context.Context, path string, reqBody []byte) ([]byte, error) {
	return doWithRetryPost(ctx, c.cred, "https://management.azure.com/.default", nil, path, armBaseURL, reqBody)
}

// ---------------------------------------------------------------------------
// paginateARM — pagination helper for ARM API list responses
// ---------------------------------------------------------------------------

// paginateARM fetches all pages of an ARM API list endpoint and returns the
// deserialized items. It follows nextLink until exhausted.
func paginateARM[T any](ctx context.Context, client ARMClient, path string) ([]T, error) {
	var all []T
	currentPath := path

	for {
		body, err := client.Get(ctx, currentPath)
		if err != nil {
			return all, err
		}

		var resp armListResponse
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
// ARM API intermediate deserialization types
// ---------------------------------------------------------------------------

// armRoleAssignment represents the ARM API response shape for a role assignment.
type armRoleAssignment struct {
	ID         string                       `json:"id"`
	Name       string                       `json:"name"`
	Properties armRoleAssignmentProperties  `json:"properties"`
}

type armRoleAssignmentProperties struct {
	RoleDefinitionID string `json:"roleDefinitionId"`
	PrincipalID      string `json:"principalId"`
	PrincipalType    string `json:"principalType,omitempty"`
	Scope            string `json:"scope"`
	Condition        string `json:"condition,omitempty"`
}

// armRoleDefinition represents the ARM API response shape for a role definition.
type armRoleDefinition struct {
	ID         string                       `json:"id"`
	Name       string                       `json:"name"`
	Properties armRoleDefinitionProperties  `json:"properties"`
}

type armRoleDefinitionProperties struct {
	RoleName         string              `json:"roleName"`
	Description      string              `json:"description,omitempty"`
	RoleType         string              `json:"type"`
	Permissions      []armPermission     `json:"permissions,omitempty"`
	AssignableScopes []string            `json:"assignableScopes,omitempty"`
}

type armPermission struct {
	Actions        []string `json:"actions,omitempty"`
	NotActions     []string `json:"notActions,omitempty"`
	DataActions    []string `json:"dataActions,omitempty"`
	NotDataActions []string `json:"notDataActions,omitempty"`
}

// ---------------------------------------------------------------------------
// RBACCollector
// ---------------------------------------------------------------------------

// RBACCollector collects Azure RBAC role assignments and definitions for
// one or more subscriptions via the ARM REST API.
type RBACCollector struct {
	client ARMClient
}

// NewRBACCollector creates a collector that authenticates with the given
// Azure credential.
func NewRBACCollector(cred azcore.TokenCredential) *RBACCollector {
	return &RBACCollector{
		client: &azureARMClient{cred: newCachedCredential(cred)},
	}
}

// newRBACCollectorWithClient creates a collector with a custom ARMClient.
// This is the primary constructor used by tests.
func newRBACCollectorWithClient(client ARMClient) *RBACCollector {
	return &RBACCollector{
		client: client,
	}
}

// Collect gathers RBAC role assignments and definitions for each subscription.
// If a subscription fails, it is logged and skipped — other subscriptions are
// still collected.
func (c *RBACCollector) Collect(ctx context.Context, subscriptionIDs []string) ([]*types.RBACData, error) {
	var results []*types.RBACData

	for _, subID := range subscriptionIDs {
		data, err := c.collectSubscription(ctx, subID)
		if err != nil {
			slog.Warn("failed to collect RBAC data for subscription", "subscriptionId", subID, "error", err)
			continue
		}
		results = append(results, data)

	}

	return results, nil
}

// collectSubscription gathers role assignments and definitions for a single subscription.
func (c *RBACCollector) collectSubscription(ctx context.Context, subID string) (*types.RBACData, error) {
	data := &types.RBACData{
		SubscriptionID: subID,
		Definitions:    store.NewMap[types.RoleDefinition](),
	}

	// 1. Role Assignments
	assignmentsPath := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01", subID)
	armAssignments, err := paginateARM[armRoleAssignment](ctx, c.client, assignmentsPath)
	if err != nil {
		return nil, fmt.Errorf("collecting role assignments: %w", err)
	}

	for _, a := range armAssignments {
		data.Assignments = append(data.Assignments, types.RoleAssignment{
			ID:               a.ID,
			PrincipalID:      a.Properties.PrincipalID,
			RoleDefinitionID: a.Properties.RoleDefinitionID,
			Scope:            a.Properties.Scope,
			PrincipalType:    a.Properties.PrincipalType,
			Condition:        a.Properties.Condition,
		})
	}

	// 2. Role Definitions
	definitionsPath := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01", subID)
	armDefs, err := paginateARM[armRoleDefinition](ctx, c.client, definitionsPath)
	if err != nil {
		slog.Warn("failed to collect role definitions", "subscriptionId", subID, "error", err)
		// Return what we have — assignments are still useful without definitions.
		return data, nil
	}

	for _, d := range armDefs {
		var perms []types.RolePermission
		for _, p := range d.Properties.Permissions {
			perms = append(perms, types.RolePermission{
				Actions:        p.Actions,
				NotActions:     p.NotActions,
				DataActions:    p.DataActions,
				NotDataActions: p.NotDataActions,
			})
		}
		data.Definitions.Set(d.ID, types.RoleDefinition{
			ID:          d.ID,
			RoleName:    d.Properties.RoleName,
			Description: d.Properties.Description,
			RoleType:    d.Properties.RoleType,
			Permissions: perms,
		})
	}

	return data, nil
}
