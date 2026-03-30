package recon

import (
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGCPBillingMetadataModule_Metadata(t *testing.T) {
	m := &GCPBillingMetadataModule{}
	assert.Equal(t, "billing-metadata", m.ID())
	assert.Equal(t, "GCP Billing Metadata", m.Name())
	assert.Equal(t, plugin.PlatformGCP, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "moderate", m.OpsecLevel())
	assert.NotEmpty(t, m.Authors())
	assert.NotEmpty(t, m.Description())
	assert.NotEmpty(t, m.References())
	assert.Nil(t, m.SupportedResourceTypes())
	assert.NotNil(t, m.Parameters())
}

func TestGCPBillingSummary_String_Empty(t *testing.T) {
	s := &output.GCPBillingSummary{}
	out := s.String()
	assert.Contains(t, out, "GCP Billing Accounts:")
	assert.Contains(t, out, "(none)")
	assert.Contains(t, out, "Project Billing Bindings:")
}

func TestGCPBillingSummary_String_WithData(t *testing.T) {
	s := &output.GCPBillingSummary{
		BillingAccounts: []output.BillingAccountInfo{
			{
				Name:        "billingAccounts/012345-ABCDEF-678901",
				DisplayName: "My Billing Account",
				Open:        true,
			},
			{
				Name:            "billingAccounts/999999-ZZZZZ-000000",
				DisplayName:     "Sub Account",
				Open:            false,
				MasterAccountID: "billingAccounts/012345-ABCDEF-678901",
			},
		},
		ProjectBindings: []output.ProjectBinding{
			{
				ProjectID:        "my-project-123",
				BillingAccountID: "billingAccounts/012345-ABCDEF-678901",
				BillingEnabled:   true,
			},
			{
				ProjectID:        "disabled-project",
				BillingAccountID: "billingAccounts/012345-ABCDEF-678901",
				BillingEnabled:   false,
			},
		},
	}

	out := s.String()

	// Verify billing accounts table.
	assert.Contains(t, out, "GCP Billing Accounts:")
	assert.Contains(t, out, "billingAccounts/012345-ABCDEF-678901")
	assert.Contains(t, out, "My Billing Account")
	assert.Contains(t, out, "Sub Account")

	// Verify project bindings table.
	assert.Contains(t, out, "Project Billing Bindings:")
	assert.Contains(t, out, "my-project-123")
	assert.Contains(t, out, "disabled-project")

	// Verify table structure: headers and separator rows.
	lines := strings.Split(out, "\n")
	hasSeparator := false
	for _, line := range lines {
		if strings.Contains(line, "-|-") {
			hasSeparator = true
			break
		}
	}
	require.True(t, hasSeparator, "expected markdown table separator row")
}
