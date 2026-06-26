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

		globalAddrName := fixture.Output("global_address_name")
		assertContainsResource(t, resources, "compute.googleapis.com/GlobalAddress", globalAddrName)
	})

	t.Run("ListByResourceID fetches fixture resources", func(t *testing.T) {
		zone := fixture.Output("instance_zone")
		region := regionFromZone(zone)
		cases := []struct {
			name         string
			resourceType string
			resourceID   string
			wantName     string
		}{
			{
				name:         "bucket",
				resourceType: "storage.googleapis.com/Bucket",
				resourceID:   fixture.Output("public_bucket_name"),
				wantName:     fixture.Output("public_bucket_name"),
			},
			{
				name:         "compute instance",
				resourceType: "compute.googleapis.com/Instance",
				resourceID:   "projects/" + projectID + "/zones/" + zone + "/instances/" + fixture.Output("instance_name"),
				wantName:     fixture.Output("instance_name"),
			},
			{
				name:         "sql instance",
				resourceType: "sqladmin.googleapis.com/Instance",
				resourceID:   fixture.Output("sql_instance_name"),
				wantName:     fixture.Output("sql_instance_name"),
			},
			{
				name:         "dns zone",
				resourceType: "dns.googleapis.com/ManagedZone",
				resourceID:   fixture.Output("dns_zone_name"),
				wantName:     fixture.Output("dns_zone_name"),
			},
			{
				name:         "cloud function",
				resourceType: "cloudfunctions.googleapis.com/Function",
				resourceID:   "projects/" + projectID + "/locations/" + region + "/functions/" + fixture.Output("function_name"),
				wantName:     fixture.Output("function_name"),
			},
			{
				name:         "cloud run service",
				resourceType: "run.googleapis.com/Service",
				resourceID:   "projects/" + projectID + "/locations/" + region + "/services/" + fixture.Output("cloud_run_public_name"),
				wantName:     fixture.Output("cloud_run_public_name"),
			},
			{
				name:         "regional address",
				resourceType: "compute.googleapis.com/Address",
				resourceID:   "projects/" + projectID + "/regions/" + region + "/addresses/" + fixture.Output("regional_address_name"),
				wantName:     fixture.Output("regional_address_name"),
			},
			{
				name:         "global address",
				resourceType: "compute.googleapis.com/GlobalAddress",
				resourceID:   "projects/" + projectID + "/global/addresses/" + fixture.Output("global_address_name"),
				wantName:     fixture.Output("global_address_name"),
			},
			{
				name:         "regional forwarding rule",
				resourceType: "compute.googleapis.com/ForwardingRule",
				resourceID:   "projects/" + projectID + "/regions/" + region + "/forwardingRules/" + fixture.Output("regional_forwarding_rule_name"),
				wantName:     fixture.Output("regional_forwarding_rule_name"),
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				directResources := listResourceByID(t, e, ResourceIDInput{
					ProjectID:    projectID,
					ResourceType: tc.resourceType,
					ResourceID:   tc.resourceID,
				})
				require.Len(t, directResources, 1)
				assert.Equal(t, tc.resourceType, directResources[0].ResourceType)
				assert.Equal(t, projectID, directResources[0].ProjectID)
				assertResourceMatchesName(t, directResources[0], tc.wantName)
			})
		}
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

func listResourceByID(t *testing.T, e *Enumerator, input ResourceIDInput) []output.GCPResource {
	t.Helper()
	out := pipeline.New[output.GCPResource]()
	var listErr error
	go func() {
		defer out.Close()
		listErr = e.ListByResourceID(input, out)
	}()
	resources, err := out.Collect()
	require.NoError(t, err)
	require.NoError(t, listErr)
	return resources
}

func assertContainsResource(t *testing.T, resources []output.GCPResource, resourceType, nameSubstr string) {
	t.Helper()
	for _, r := range resources {
		if r.ResourceType == resourceType && resourceMatchesName(r, nameSubstr) {
			return
		}
	}
	t.Errorf("expected resource of type %q containing %q in %d results", resourceType, nameSubstr, len(resources))
}

func assertResourceMatchesName(t *testing.T, r output.GCPResource, nameSubstr string) {
	t.Helper()
	assert.Truef(t, resourceMatchesName(r, nameSubstr),
		"expected resource %q (%s) to match %q", r.ResourceID, r.DisplayName, nameSubstr)
}

func resourceMatchesName(r output.GCPResource, nameSubstr string) bool {
	return r.DisplayName == nameSubstr || strings.Contains(r.DisplayName, nameSubstr) || strings.Contains(r.ResourceID, nameSubstr)
}

func regionFromZone(zone string) string {
	parts := strings.Split(zone, "-")
	if len(parts) < 3 {
		return zone
	}
	return strings.Join(parts[:len(parts)-1], "-")
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
