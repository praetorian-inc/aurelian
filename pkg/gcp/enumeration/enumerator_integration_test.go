//go:build integration

package enumeration

import (
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnumeratorIntegration(t *testing.T) {
	fixture := testutil.NewGCPFixture(t, "gcp/recon/list")
	fixture.Setup()

	projectID := fixture.Output("project_id")

	opts := plugin.GCPCommonRecon{
		Concurrency: 5,
	}
	e := NewEnumerator(opts)

	out := pipeline.New[output.GCPResource]()
	go func() {
		defer out.Close()
		err := e.ListForProject(projectID, out)
		require.NoError(t, err)
	}()

	var resources []output.GCPResource
	for r := range out.Range() {
		resources = append(resources, r)
	}

	require.NotEmpty(t, resources, "enumerator should discover resources")

	// Collect discovered resource types
	typeSet := make(map[string]bool)
	for _, r := range resources {
		typeSet[r.ResourceType] = true
	}
	assert.GreaterOrEqual(t, len(typeSet), 5,
		"expected at least 5 distinct resource types, got %d: %v", len(typeSet), typeSet)

	t.Run("discovers storage buckets", func(t *testing.T) {
		bucketName := fixture.Output("public_bucket_name")
		assertContainsResource(t, resources, "storage.googleapis.com/Bucket", bucketName)
	})

	t.Run("discovers compute instances", func(t *testing.T) {
		instanceName := fixture.Output("instance_name")
		assertContainsResource(t, resources, "compute.googleapis.com/Instance", instanceName)
	})

	t.Run("discovers sql instances", func(t *testing.T) {
		sqlName := fixture.Output("sql_instance_name")
		assertContainsResource(t, resources, "sqladmin.googleapis.com/Instance", sqlName)
	})

	t.Run("discovers dns zones", func(t *testing.T) {
		zoneName := fixture.Output("dns_zone_name")
		assertContainsResource(t, resources, "dns.googleapis.com/ManagedZone", zoneName)
	})

	t.Run("discovers cloud functions", func(t *testing.T) {
		functionName := fixture.Output("function_name")
		assertContainsResource(t, resources, "cloudfunctions.googleapis.com/Function", functionName)
	})

	t.Run("discovers cloud run services", func(t *testing.T) {
		runName := fixture.Output("cloud_run_public_name")
		assertContainsResource(t, resources, "run.googleapis.com/Service", runName)
	})

	t.Run("discovers addresses", func(t *testing.T) {
		addrName := fixture.Output("regional_address_name")
		assertContainsResource(t, resources, "compute.googleapis.com/Address", addrName)
	})

	t.Run("ForTypes filters correctly", func(t *testing.T) {
		filtered := e.ForTypes([]string{"storage.googleapis.com/Bucket"})
		filteredOut := pipeline.New[output.GCPResource]()
		go func() {
			defer filteredOut.Close()
			err := filtered.ListForProject(projectID, filteredOut)
			require.NoError(t, err)
		}()

		var filteredResources []output.GCPResource
		for r := range filteredOut.Range() {
			filteredResources = append(filteredResources, r)
		}
		require.NotEmpty(t, filteredResources)
		for _, r := range filteredResources {
			assert.Equal(t, "storage.googleapis.com/Bucket", r.ResourceType,
				"ForTypes should only return bucket resources")
		}
	})

	t.Run("no duplicate resources", func(t *testing.T) {
		requireNoDuplicateResourceIDs(t, resources)
	})

	t.Run("all resources have required fields", func(t *testing.T) {
		for _, r := range resources {
			assert.NotEmpty(t, r.ResourceType, "ResourceType must be set")
			assert.NotEmpty(t, r.ResourceID, "ResourceID must be set")
			assert.NotEmpty(t, r.ProjectID, "ProjectID must be set for %s", r.ResourceType)
		}
	})
}

func assertContainsResource(t *testing.T, resources []output.GCPResource, resourceType, nameSubstr string) {
	t.Helper()
	for _, r := range resources {
		if r.ResourceType == resourceType && (r.DisplayName == nameSubstr || strings.Contains(r.ResourceID, nameSubstr)) {
			return
		}
	}
	t.Errorf("expected resource of type %q containing %q in %d results", resourceType, nameSubstr, len(resources))
}

func requireNoDuplicateResourceIDs(t *testing.T, resources []output.GCPResource) {
	t.Helper()
	seen := make(map[string]int)
	for _, r := range resources {
		seen[r.ResourceID]++
	}
	for id, count := range seen {
		if count > 1 {
			t.Errorf("resource %s emitted %d times, expected once", id, count)
		}
	}
}
