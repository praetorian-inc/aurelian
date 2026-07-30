package recon

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	gcsapi "google.golang.org/api/storage/v1"
)

func TestGCPTerraformStateModule_Metadata(t *testing.T) {
	m := &GCPTerraformStateModule{}
	assert.Equal(t, "terraform-state", m.ID())
	assert.Equal(t, "GCP Terraform State Detection", m.Name())
	assert.Equal(t, plugin.PlatformGCP, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.Equal(t, "moderate", m.OpsecLevel())
}

func TestGCPTerraformStateModule_Parameters(t *testing.T) {
	m := &GCPTerraformStateModule{}
	assert.NotNil(t, m.Parameters())
}

func TestGCPTerraformStateModule_Registration(t *testing.T) {
	mod, ok := plugin.Get(plugin.PlatformGCP, plugin.CategoryRecon, "terraform-state")
	assert.True(t, ok)
	assert.NotNil(t, mod)
}

func TestIsTerraformStateBucket(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"my-terraform-state", true},
		{"tfstate-prod", true},
		{"my-app-state-bucket", true},  // contains "-state-"
		{"regular-bucket", false},
		{"my-TERRAFORM-bucket", true},  // case-insensitive
		{"prod-TFSTATE-bucket", true},  // case-insensitive
		{"infra-state-store", true},    // contains "-state-"
		{"some-random-name", false},
		{"bucket-with-no-match", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isTerraformStateBucket(tc.name))
		})
	}
}

func TestHasPublicAccess(t *testing.T) {
	tests := []struct {
		name     string
		bindings []*gcsapi.PolicyBindings
		want     bool
	}{
		{
			name: "allUsers present",
			bindings: []*gcsapi.PolicyBindings{
				{Role: "roles/storage.objectViewer", Members: []string{"allUsers"}},
			},
			want: true,
		},
		{
			name: "allAuthenticatedUsers present",
			bindings: []*gcsapi.PolicyBindings{
				{Role: "roles/storage.objectViewer", Members: []string{"allAuthenticatedUsers"}},
			},
			want: true,
		},
		{
			name: "only specific users",
			bindings: []*gcsapi.PolicyBindings{
				{Role: "roles/storage.objectViewer", Members: []string{"user:admin@example.com"}},
			},
			want: false,
		},
		{
			name:     "empty bindings",
			bindings: nil,
			want:     false,
		},
		{
			name: "mixed members with allUsers",
			bindings: []*gcsapi.PolicyBindings{
				{Role: "roles/storage.admin", Members: []string{"user:admin@example.com", "allUsers"}},
			},
			want: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, hasPublicAccess(tc.bindings))
		})
	}
}
