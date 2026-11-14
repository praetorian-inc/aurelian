package enumeration

import (
	"testing"

	container "google.golang.org/api/container/v1"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// collectGCPResources drains a pipeline populated by fn and returns everything sent.
func collectGCPResources(t *testing.T, fn func(out *pipeline.P[output.GCPResource])) []output.GCPResource {
	t.Helper()
	out := pipeline.New[output.GCPResource]()
	go func() {
		defer out.Close()
		fn(out)
	}()
	var got []output.GCPResource
	for r := range out.Range() {
		got = append(got, r)
	}
	return got
}

func TestClusterLister_SendCluster_MapsFields(t *testing.T) {
	cluster := &container.Cluster{
		Name:     "prod-gke",
		Location: "us-central1",
		SelfLink: "https://container.googleapis.com/v1/projects/my-project/locations/us-central1/clusters/prod-gke",
		ResourceLabels: map[string]string{
			"env": "prod",
		},
		Status:               "RUNNING",
		Endpoint:             "203.0.113.10",
		CurrentMasterVersion: "1.29.1-gke.100",
	}

	got := collectGCPResources(t, func(out *pipeline.P[output.GCPResource]) {
		sendCluster("my-project", cluster, out)
	})

	require.Len(t, got, 1)
	r := got[0]

	// Canonical resource type is the cross-repo contract with the guard-core side.
	assert.Equal(t, "container.googleapis.com/Cluster", r.ResourceType)
	// Key on the deterministic relative self-link, distinct from the GCE instance keyspace.
	assert.Equal(t, "projects/my-project/locations/us-central1/clusters/prod-gke", r.ResourceID)
	assert.Equal(t, "my-project", r.ProjectID)
	assert.Equal(t, "prod-gke", r.DisplayName)
	assert.Equal(t, "us-central1", r.Location)
	assert.Equal(t, map[string]string{"env": "prod"}, r.Labels)
	assert.Equal(t, "RUNNING", r.Properties["status"])
	assert.Equal(t, "1.29.1-gke.100", r.Properties["currentMasterVersion"])
	assert.Equal(t, "203.0.113.10", r.Properties["endpoint"])
}

func TestClusterLister_SendCluster_FallsBackWhenSelfLinkMissing(t *testing.T) {
	cluster := &container.Cluster{
		Name:     "no-selflink",
		Location: "europe-west1",
	}

	got := collectGCPResources(t, func(out *pipeline.P[output.GCPResource]) {
		sendCluster("my-project", cluster, out)
	})

	require.Len(t, got, 1)
	assert.Equal(t,
		"projects/my-project/locations/europe-west1/clusters/no-selflink",
		got[0].ResourceID,
	)
}

func TestClusterLister_SendCluster_SurfacesEndpointInIPs(t *testing.T) {
	cluster := &container.Cluster{
		Name:     "prod-gke",
		Location: "us-central1",
		Endpoint: "203.0.113.10",
	}

	got := collectGCPResources(t, func(out *pipeline.P[output.GCPResource]) {
		sendCluster("my-project", cluster, out)
	})

	require.Len(t, got, 1)
	r := got[0]

	// The control-plane endpoint must populate the dedicated IPs field that
	// downstream enrichers/graph edges key off, mirroring InstanceLister.
	assert.Equal(t, []string{"203.0.113.10"}, r.IPs)
	// The Properties entry is kept for parity with the prior contract.
	assert.Equal(t, "203.0.113.10", r.Properties["endpoint"])
}

func TestClusterLister_SendCluster_EmptyEndpointLeavesIPsUnset(t *testing.T) {
	cluster := &container.Cluster{
		Name:     "no-endpoint",
		Location: "us-central1",
	}

	got := collectGCPResources(t, func(out *pipeline.P[output.GCPResource]) {
		sendCluster("my-project", cluster, out)
	})

	require.Len(t, got, 1)
	assert.Nil(t, got[0].IPs)
}

func TestClusterLister_ResourceTypes(t *testing.T) {
	l := NewClusterLister(nil)
	assert.Equal(t, []string{"container.googleapis.com/Cluster"}, l.ResourceTypes())
}
