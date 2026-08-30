package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// ---------------------------------------------------------------------------
// ARM API intermediate types for managed identities
// ---------------------------------------------------------------------------

type armManagedIdentity struct {
	ID         string                        `json:"id"`
	Name       string                        `json:"name"`
	Location   string                        `json:"location"`
	Properties armManagedIdentityProperties  `json:"properties"`
}

type armManagedIdentityProperties struct {
	PrincipalID string `json:"principalId"`
	ClientID    string `json:"clientId"`
	TenantID    string `json:"tenantId"`
}

// armResourceGraphResponse represents the response from Azure Resource Graph.
type armResourceGraphResponse struct {
	Data struct {
		Rows [][]json.RawMessage `json:"rows"`
	} `json:"data"`
	Count int `json:"count"`
}

// ---------------------------------------------------------------------------
// ManagedIdentityCollector
// ---------------------------------------------------------------------------

// ManagedIdentityCollector collects Azure managed identity data for one or
// more subscriptions via the ARM REST API.
type ManagedIdentityCollector struct {
	client ARMClient
}

// NewManagedIdentityCollector creates a collector that authenticates with
// the given Azure credential.
func NewManagedIdentityCollector(cred azcore.TokenCredential) *ManagedIdentityCollector {
	return &ManagedIdentityCollector{
		client: &azureARMClient{cred: newCachedCredential(cred)},
	}
}

// newManagedIdentityCollectorWithClient creates a collector with a custom ARMClient (for tests).
func newManagedIdentityCollectorWithClient(client ARMClient) *ManagedIdentityCollector {
	return &ManagedIdentityCollector{
		client: client,
	}
}

// Collect gathers user-assigned managed identities and resource identity
// attachments for each subscription.
func (c *ManagedIdentityCollector) Collect(ctx context.Context, subscriptionIDs []string) (*types.ManagedIdentityData, error) {
	data := &types.ManagedIdentityData{}

	for _, subID := range subscriptionIDs {
		identities, err := c.collectUserAssignedIdentities(ctx, subID)
		if err != nil {
			slog.Warn("failed to collect managed identities for subscription",
				"subscriptionId", subID, "error", err)
			continue
		}
		data.Identities = append(data.Identities, identities...)

	}

	// Collect resource identity attachments via Resource Graph
	attachments, err := c.collectResourceIdentityAttachments(ctx, subscriptionIDs)
	if err != nil {
		slog.Warn("failed to collect resource identity attachments", "error", err)
	} else {
		data.Attachments = attachments
	}

	return data, nil
}

// collectUserAssignedIdentities lists all user-assigned managed identities in a subscription.
func (c *ManagedIdentityCollector) collectUserAssignedIdentities(ctx context.Context, subID string) ([]types.ManagedIdentity, error) {
	path := fmt.Sprintf("/subscriptions/%s/providers/Microsoft.ManagedIdentity/userAssignedIdentities?api-version=2023-01-31", subID)
	armIdentities, err := paginateARM[armManagedIdentity](ctx, c.client, path)
	if err != nil {
		return nil, fmt.Errorf("listing managed identities: %w", err)
	}

	var identities []types.ManagedIdentity
	for _, ami := range armIdentities {
		mi := types.ManagedIdentity{
			ID:             strings.ToLower(ami.ID),
			Name:           ami.Name,
			Location:       ami.Location,
			PrincipalID:    ami.Properties.PrincipalID,
			ClientID:       ami.Properties.ClientID,
			TenantID:       ami.Properties.TenantID,
			SubscriptionID: subID,
		}
		// Extract resource group from ID
		if parts := strings.Split(ami.ID, "/"); len(parts) >= 5 {
			for i, p := range parts {
				if strings.EqualFold(p, "resourceGroups") && i+1 < len(parts) {
					mi.ResourceGroup = parts[i+1]
					break
				}
			}
		}
		identities = append(identities, mi)
	}

	return identities, nil
}

// collectResourceIdentityAttachments uses Azure Resource Graph to find resources
// with managed identities attached.
func (c *ManagedIdentityCollector) collectResourceIdentityAttachments(ctx context.Context, subscriptionIDs []string) ([]types.ResourceIdentityAttachment, error) {
	if len(subscriptionIDs) == 0 {
		return nil, nil
	}

	// Resource Graph query body
	query := `Resources | where isnotnull(identity) | where identity.type != '' | project id, name, type, subscriptionId, identity`
	reqBody, err := json.Marshal(map[string]any{
		"query":         query,
		"subscriptions": subscriptionIDs,
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling query: %w", err)
	}

	body, err := c.client.Post(ctx, "/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01", reqBody)
	if err != nil {
		return nil, fmt.Errorf("resource graph query: %w", err)
	}

	// Parse the tabular response
	var graphResp struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &graphResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	// Resource Graph can return data as array of objects
	var rows []struct {
		ID             string `json:"id"`
		Name           string `json:"name"`
		Type           string `json:"type"`
		SubscriptionID string `json:"subscriptionId"`
		Identity       struct {
			Type                   string                            `json:"type"`
			PrincipalID            string                            `json:"principalId"`
			UserAssignedIdentities map[string]map[string]interface{} `json:"userAssignedIdentities"`
		} `json:"identity"`
	}
	if err := json.Unmarshal(graphResp.Data, &rows); err != nil {
		// Try tabular format
		var tabular struct {
			Columns []struct {
				Name string `json:"name"`
			} `json:"columns"`
			Rows [][]json.RawMessage `json:"rows"`
		}
		if err2 := json.Unmarshal(graphResp.Data, &tabular); err2 != nil {
			return nil, fmt.Errorf("parsing data: %w (also tried tabular: %w)", err, err2)
		}
		// Parse tabular rows
		for _, row := range tabular.Rows {
			if len(row) < 5 {
				continue
			}
			var id, name, rType, subID string
			json.Unmarshal(row[0], &id)
			json.Unmarshal(row[1], &name)
			json.Unmarshal(row[2], &rType)
			json.Unmarshal(row[3], &subID)

			var identity struct {
				Type                   string                            `json:"type"`
				PrincipalID            string                            `json:"principalId"`
				UserAssignedIdentities map[string]map[string]interface{} `json:"userAssignedIdentities"`
			}
			json.Unmarshal(row[4], &identity)

			rows = append(rows, struct {
				ID             string `json:"id"`
				Name           string `json:"name"`
				Type           string `json:"type"`
				SubscriptionID string `json:"subscriptionId"`
				Identity       struct {
					Type                   string                            `json:"type"`
					PrincipalID            string                            `json:"principalId"`
					UserAssignedIdentities map[string]map[string]interface{} `json:"userAssignedIdentities"`
				} `json:"identity"`
			}{
				ID: id, Name: name, Type: rType, SubscriptionID: subID, Identity: identity,
			})
		}
	}

	var attachments []types.ResourceIdentityAttachment
	for _, r := range rows {
		att := types.ResourceIdentityAttachment{
			ResourceID:     r.ID,
			ResourceName:   r.Name,
			ResourceType:   r.Type,
			SubscriptionID: r.SubscriptionID,
			IdentityType:   r.Identity.Type,
			PrincipalID:    r.Identity.PrincipalID,
		}
		for uaID := range r.Identity.UserAssignedIdentities {
			att.UserAssignedIDs = append(att.UserAssignedIDs, strings.ToLower(uaID))
		}
		attachments = append(attachments, att)
	}

	return attachments, nil
}
