package enrichers

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/stretchr/testify/assert"
)

func TestEnrichCloudRunIAM_AnonymousAccess(t *testing.T) {
	r := &output.GCPResource{
		ResourceType: "run.googleapis.com/Service",
		ResourceID:   "projects/proj/locations/us-central1/services/my-svc",
		Properties:   make(map[string]any),
	}
	bindings := []iamBinding{
		{Role: "roles/run.invoker", Members: []string{"allUsers"}},
	}
	enrichCloudRunIAMWithBindings(r, bindings)

	assert.Equal(t, true, r.Properties["AnonymousAccess"])
	info := r.Properties["AnonymousAccessInfo"].(map[string]any)
	assert.Equal(t, "roles/run.invoker", info["role"])
	assert.Equal(t, "allUsers", info["member"])
	assert.NotNil(t, r.Properties["IAMBindings"])
}

func TestEnrichCloudRunIAM_NoAnonymousAccess(t *testing.T) {
	r := &output.GCPResource{
		ResourceType: "run.googleapis.com/Service",
		ResourceID:   "projects/proj/locations/us-central1/services/my-svc",
		Properties:   make(map[string]any),
	}
	bindings := []iamBinding{
		{Role: "roles/run.invoker", Members: []string{"serviceAccount:sa@proj.iam.gserviceaccount.com"}},
	}
	enrichCloudRunIAMWithBindings(r, bindings)

	_, hasAnon := r.Properties["AnonymousAccess"]
	assert.False(t, hasAnon)
	assert.NotNil(t, r.Properties["IAMBindings"])
}

func TestEnrichCloudRunIAM_AllAuthenticatedUsers(t *testing.T) {
	r := &output.GCPResource{
		ResourceType: "run.googleapis.com/Service",
		ResourceID:   "projects/proj/locations/us-central1/services/my-svc",
		Properties:   make(map[string]any),
	}
	bindings := []iamBinding{
		{Role: "roles/run.invoker", Members: []string{"allAuthenticatedUsers"}},
	}
	enrichCloudRunIAMWithBindings(r, bindings)

	assert.Equal(t, true, r.Properties["AnonymousAccess"])
	info := r.Properties["AnonymousAccessInfo"].(map[string]any)
	assert.Equal(t, "allAuthenticatedUsers", info["member"])
}

func TestEnrichCloudRunIAM_NilProperties(t *testing.T) {
	r := &output.GCPResource{
		ResourceType: "run.googleapis.com/Service",
		ResourceID:   "projects/proj/locations/us-central1/services/my-svc",
	}
	bindings := []iamBinding{
		{Role: "roles/viewer", Members: []string{"user:viewer@example.com"}},
	}
	enrichCloudRunIAMWithBindings(r, bindings)

	assert.NotNil(t, r.Properties)
	assert.NotNil(t, r.Properties["IAMBindings"])
}
