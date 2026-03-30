package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

func TestGCPOrgPoliciesModule_Metadata(t *testing.T) {
	m := &GCPOrgPoliciesModule{}
	assert.Equal(t, "org-policies", m.ID())
	assert.Equal(t, "GCP Organization Policies", m.Name())
	assert.Equal(t, plugin.PlatformGCP, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "moderate", m.OpsecLevel())
	assert.NotEmpty(t, m.Authors())
	assert.NotEmpty(t, m.Description())
	assert.NotEmpty(t, m.References())
	assert.NotNil(t, m.Parameters())
}

func TestGCPOrgPoliciesModule_SupportedResourceTypes(t *testing.T) {
	m := &GCPOrgPoliciesModule{}
	types := m.SupportedResourceTypes()
	assert.Equal(t, []string{"orgpolicy.googleapis.com/Policy"}, types)
}

func TestExtractConstraintShortName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"constraints/compute.disableSerialPortAccess", "compute.disableSerialPortAccess"},
		{"constraints/iam.allowedPolicyMemberDomains", "iam.allowedPolicyMemberDomains"},
		{"bareConstraint", "bareConstraint"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractConstraintShortName(tt.input))
		})
	}
}

func TestExtractResourceID(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"organizations/123456", "123456"},
		{"folders/789", "789"},
		{"projects/my-project", "my-project"},
		{"bare-id", "bare-id"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractResourceID(tt.input))
		})
	}
}
