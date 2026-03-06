package enrichers

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/stretchr/testify/assert"
)

func TestEnrichFunctionIAM_AnonymousAccess(t *testing.T) {
	r := &output.GCPResource{
		ResourceType: "cloudfunctions.googleapis.com/Function",
		ResourceID:   "projects/proj/locations/us-central1/functions/my-func",
		Properties:   make(map[string]any),
	}
	bindings := []iamBinding{
		{Role: "roles/cloudfunctions.invoker", Members: []string{"allUsers"}},
	}
	enrichIAMBindings(r, bindings)

	assert.Equal(t, true, r.Properties["AnonymousAccess"])
	assert.NotNil(t, r.Properties["IAMBindings"])
}

func TestEnrichFunctionIAM_NoAnonymousAccess(t *testing.T) {
	r := &output.GCPResource{
		ResourceType: "cloudfunctions.googleapis.com/Function",
		ResourceID:   "projects/proj/locations/us-central1/functions/my-func",
		Properties:   make(map[string]any),
	}
	bindings := []iamBinding{
		{Role: "roles/cloudfunctions.invoker", Members: []string{"user:admin@example.com"}},
	}
	enrichIAMBindings(r, bindings)

	_, hasAnon := r.Properties["AnonymousAccess"]
	assert.False(t, hasAnon)
	assert.NotNil(t, r.Properties["IAMBindings"])
}

func TestEnrichFunctionIAM_AllAuthenticatedUsers(t *testing.T) {
	r := &output.GCPResource{
		ResourceType: "cloudfunctions.googleapis.com/Function",
		ResourceID:   "projects/proj/locations/us-central1/functions/my-func",
		Properties:   make(map[string]any),
	}
	bindings := []iamBinding{
		{Role: "roles/cloudfunctions.invoker", Members: []string{"allAuthenticatedUsers"}},
	}
	enrichIAMBindings(r, bindings)

	assert.Equal(t, true, r.Properties["AnonymousAccess"])
	info := r.Properties["AnonymousAccessInfo"].(map[string]any)
	assert.Equal(t, "allAuthenticatedUsers", info["member"])
}

func TestEnrichFunctionIAM_NilProperties(t *testing.T) {
	r := &output.GCPResource{
		ResourceType: "cloudfunctions.googleapis.com/Function",
		ResourceID:   "projects/proj/locations/us-central1/functions/my-func",
	}
	bindings := []iamBinding{
		{Role: "roles/viewer", Members: []string{"user:viewer@example.com"}},
	}
	enrichIAMBindings(r, bindings)

	assert.NotNil(t, r.Properties)
	assert.NotNil(t, r.Properties["IAMBindings"])
}
