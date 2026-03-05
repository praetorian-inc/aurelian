//go:build integration

package recon_test

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/gcp/enrichers"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGCPListAllResources(t *testing.T) {
	fixture := testutil.NewGCPFixture(t, "gcp/recon/list")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformGCP, plugin.CategoryRecon, "list-all")
	if !ok {
		t.Fatal("gcp list-all module not registered")
	}

	projectID := fixture.Output("project_id")

	cfg := plugin.Config{
		Args: map[string]any{
			"project-id":    []string{projectID},
			"resource-type": []string{"all"},
		},
		Context: context.Background(),
	}

	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	var resources []output.GCPResource
	var risks []output.AurelianRisk
	for m := range p2.Range() {
		switch v := m.(type) {
		case output.GCPResource:
			resources = append(resources, v)
		case output.AurelianRisk:
			risks = append(risks, v)
		}
	}
	require.NoError(t, p2.Wait())
	require.NotEmpty(t, resources, "should discover at least one GCP resource")

	// Assert at least 8 distinct resource types are discovered.
	resourceTypes := make(map[string]bool)
	for _, r := range resources {
		resourceTypes[r.ResourceType] = true
	}
	assert.GreaterOrEqual(t, len(resourceTypes), 8,
		"expected at least 8 distinct resource types, got %d: %v", len(resourceTypes), resourceTypes)

	t.Run("discovers storage buckets", func(t *testing.T) {
		publicBucket := fixture.Output("public_bucket_name")
		privateBucket := fixture.Output("private_bucket_name")

		var found []output.GCPResource
		for _, r := range resources {
			if r.ResourceType == "storage.googleapis.com/Bucket" {
				found = append(found, r)
			}
		}
		require.GreaterOrEqual(t, len(found), 2, "expected at least 2 storage buckets")

		assertResourceByName(t, found, publicBucket, projectID, "storage.googleapis.com/Bucket")
		assertResourceByName(t, found, privateBucket, projectID, "storage.googleapis.com/Bucket")
	})

	t.Run("discovers compute instances", func(t *testing.T) {
		instanceName := fixture.Output("instance_name")

		var found []output.GCPResource
		for _, r := range resources {
			if r.ResourceType == "compute.googleapis.com/Instance" {
				found = append(found, r)
			}
		}
		require.NotEmpty(t, found, "expected at least 1 compute instance")
		assertResourceByName(t, found, instanceName, projectID, "compute.googleapis.com/Instance")
	})

	t.Run("discovers sql instances", func(t *testing.T) {
		sqlName := fixture.Output("sql_instance_name")

		var found []output.GCPResource
		for _, r := range resources {
			if r.ResourceType == "sqladmin.googleapis.com/Instance" {
				found = append(found, r)
			}
		}
		require.NotEmpty(t, found, "expected at least 1 SQL instance")
		assertResourceByName(t, found, sqlName, projectID, "sqladmin.googleapis.com/Instance")
	})

	t.Run("discovers dns zones", func(t *testing.T) {
		zoneName := fixture.Output("dns_zone_name")

		var found []output.GCPResource
		for _, r := range resources {
			if r.ResourceType == "dns.googleapis.com/ManagedZone" {
				found = append(found, r)
			}
		}
		require.NotEmpty(t, found, "expected at least 1 DNS managed zone")
		assertResourceByName(t, found, zoneName, projectID, "dns.googleapis.com/ManagedZone")
	})

	t.Run("discovers cloud functions", func(t *testing.T) {
		functionName := fixture.Output("function_name")

		var found []output.GCPResource
		for _, r := range resources {
			if r.ResourceType == "cloudfunctions.googleapis.com/Function" {
				found = append(found, r)
			}
		}
		require.NotEmpty(t, found, "expected at least 1 cloud function")
		assertResourceByName(t, found, functionName, projectID, "cloudfunctions.googleapis.com/Function")
	})

	t.Run("discovers cloud run services", func(t *testing.T) {
		publicRunName := fixture.Output("cloud_run_public_name")
		privateRunName := fixture.Output("cloud_run_private_name")

		var found []output.GCPResource
		for _, r := range resources {
			if r.ResourceType == "run.googleapis.com/Service" {
				found = append(found, r)
			}
		}
		require.GreaterOrEqual(t, len(found), 2, "expected at least 2 cloud run services")

		assertResourceByName(t, found, publicRunName, projectID, "run.googleapis.com/Service")
		assertResourceByName(t, found, privateRunName, projectID, "run.googleapis.com/Service")
	})

	t.Run("discovers addresses", func(t *testing.T) {
		globalAddr := fixture.Output("global_address_name")
		regionalAddr := fixture.Output("regional_address_name")

		var found []output.GCPResource
		for _, r := range resources {
			if r.ResourceType == "compute.googleapis.com/GlobalAddress" || r.ResourceType == "compute.googleapis.com/Address" {
				found = append(found, r)
			}
		}
		require.GreaterOrEqual(t, len(found), 2, "expected at least 2 addresses")

		assertResourceByName(t, found, globalAddr, projectID, "compute.googleapis.com/GlobalAddress")
		assertResourceByName(t, found, regionalAddr, projectID, "compute.googleapis.com/Address")
	})

	t.Run("discovers forwarding rules", func(t *testing.T) {
		fwdRuleName := fixture.Output("regional_forwarding_rule_name")

		var found []output.GCPResource
		for _, r := range resources {
			if r.ResourceType == "compute.googleapis.com/ForwardingRule" || r.ResourceType == "compute.googleapis.com/GlobalForwardingRule" {
				found = append(found, r)
			}
		}
		require.GreaterOrEqual(t, len(found), 1, "expected at least 1 forwarding rule")

		assertResourceByName(t, found, fwdRuleName, projectID, "compute.googleapis.com/ForwardingRule")
	})

	t.Run("discovers private compute instances", func(t *testing.T) {
		privateInstanceName := fixture.Output("private_instance_name")

		var found []output.GCPResource
		for _, r := range resources {
			if r.ResourceType == "compute.googleapis.com/Instance" {
				found = append(found, r)
			}
		}
		assertResourceByName(t, found, privateInstanceName, projectID, "compute.googleapis.com/Instance")
	})

	t.Run("discovers private dns zones", func(t *testing.T) {
		privateDNSZone := fixture.Output("private_dns_zone_name")

		var found []output.GCPResource
		for _, r := range resources {
			if r.ResourceType == "dns.googleapis.com/ManagedZone" {
				found = append(found, r)
			}
		}
		assertResourceByName(t, found, privateDNSZone, projectID, "dns.googleapis.com/ManagedZone")
	})

	t.Run("all resources have required fields", func(t *testing.T) {
		for _, r := range resources {
			assert.NotEmpty(t, r.ResourceType, "ResourceType must be set")
			assert.NotEmpty(t, r.ResourceID, "ResourceID must be set")
			// Hierarchy resources (organizations, folders) don't have ProjectID
			if r.ResourceType != "organizations" && r.ResourceType != "folders" && r.ResourceType != "projects" {
				assert.NotEmpty(t, r.ProjectID, "ProjectID must be set for %s", r.ResourceType)
			}
		}
	})
}

// assertResourceByName checks that at least one resource in the slice has a
// DisplayName or ResourceID containing the given name, and validates its
// ProjectID and ResourceType fields.
func assertResourceByName(t *testing.T, resources []output.GCPResource, name, projectID, resourceType string) {
	t.Helper()
	for _, r := range resources {
		if containsName(r, name) {
			assert.Equal(t, projectID, r.ProjectID, "ProjectID mismatch for %s", name)
			assert.Equal(t, resourceType, r.ResourceType, "ResourceType mismatch for %s", name)
			assert.NotEmpty(t, r.ResourceID, "ResourceID must be set for %s", name)
			return
		}
	}
	t.Errorf("expected resource with name %q in %d results", name, len(resources))
}

func containsName(r output.GCPResource, name string) bool {
	return r.DisplayName == name || strings.HasSuffix(r.ResourceID, name) || strings.Contains(r.ResourceID, name)
}
