package iam

import (
	"context"
	"log/slog"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// ---------------------------------------------------------------------------
// PIM schedule instance — intermediate struct for Graph API deserialization
// ---------------------------------------------------------------------------

// pimScheduleInstance maps the JSON fields returned by the Graph API PIM
// endpoints to Go fields. The Graph API uses "directoryScopeId" which we
// map to the Scope field on types.PIMRoleAssignment.
type pimScheduleInstance struct {
	ID               string `json:"id"`
	PrincipalID      string `json:"principalId"`
	RoleDefinitionID string `json:"roleDefinitionId"`
	DirectoryScopeID string `json:"directoryScopeId"`
	StartDateTime    string `json:"startDateTime,omitempty"`
	EndDateTime      string `json:"endDateTime,omitempty"`
}

// toRoleAssignment converts a pimScheduleInstance to a types.PIMRoleAssignment
// with the given assignment type ("active" or "eligible").
func (p pimScheduleInstance) toRoleAssignment(assignmentType string) types.PIMRoleAssignment {
	return types.PIMRoleAssignment{
		ID:               p.ID,
		PrincipalID:      p.PrincipalID,
		RoleDefinitionID: p.RoleDefinitionID,
		Scope:            p.DirectoryScopeID,
		AssignmentType:   assignmentType,
		StartDateTime:    p.StartDateTime,
		EndDateTime:      p.EndDateTime,
	}
}

// ---------------------------------------------------------------------------
// PIMCollector
// ---------------------------------------------------------------------------

const (
	pimActivePath   = "/roleManagement/directory/roleAssignmentScheduleInstances"
	pimEligiblePath = "/roleManagement/directory/roleEligibilityScheduleInstances"
)

// PIMCollector collects PIM role assignment data from Microsoft Graph.
// It reuses the GraphClient interface and paginate helper from entra.go.
type PIMCollector struct {
	client     GraphClient
	batchDelay time.Duration
}

// NewPIMCollector creates a collector that authenticates with the given
// Azure credential.
func NewPIMCollector(cred azcore.TokenCredential) *PIMCollector {
	return &PIMCollector{
		client:     &azureGraphClient{cred: cred},
		batchDelay: 200 * time.Millisecond,
	}
}

// newPIMCollectorWithClient creates a collector with a custom GraphClient.
// This is the primary constructor used by tests.
func newPIMCollectorWithClient(client GraphClient) *PIMCollector {
	return &PIMCollector{
		client:     client,
		batchDelay: 0, // no delay in tests
	}
}

// Collect gathers active and eligible PIM role assignments and returns the
// consolidated result. PIM requires Azure AD Premium P2; if the API returns
// an error the collector logs a warning and returns empty data (non-fatal),
// matching nebula behavior.
func (c *PIMCollector) Collect(ctx context.Context) (*types.PIMData, error) {
	data := &types.PIMData{}

	// 1. Active PIM assignments
	activeInstances, err := paginate[pimScheduleInstance](ctx, c.client, pimActivePath)
	if err != nil {
		slog.Warn("failed to collect active PIM assignments (may require Azure AD Premium P2)", "error", err)
	} else {
		for _, inst := range activeInstances {
			data.ActiveAssignments = append(data.ActiveAssignments, inst.toRoleAssignment("active"))
		}
	}

	if c.batchDelay > 0 {
		time.Sleep(c.batchDelay)
	}

	// 2. Eligible PIM assignments
	eligibleInstances, err := paginate[pimScheduleInstance](ctx, c.client, pimEligiblePath)
	if err != nil {
		slog.Warn("failed to collect eligible PIM assignments (may require Azure AD Premium P2)", "error", err)
	} else {
		for _, inst := range eligibleInstances {
			data.EligibleAssignments = append(data.EligibleAssignments, inst.toRoleAssignment("eligible"))
		}
	}

	return data, nil
}
