//go:build integration

package recon_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/gcp/enrichers"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeProof unmarshals a Risk's proof bytes into a structured capmodel.Proof.
func decodeProof(t *testing.T, risk capmodel.Risk) capmodel.Proof {
	t.Helper()
	var proof capmodel.Proof
	require.NoError(t, json.Unmarshal(risk.Proof, &proof), "proof should decode into capmodel.Proof")
	return proof
}

// sectionByTitle returns the named proof section, failing if it is absent.
func sectionByTitle(t *testing.T, proof capmodel.Proof, title string) capmodel.ProofSection {
	t.Helper()
	for _, s := range proof.Sections {
		if s.Title == title {
			return s
		}
	}
	require.Failf(t, "section not found", "proof has no %q section", title)
	return capmodel.ProofSection{}
}

// keyValueMap flattens a section's key/value rows into a map for assertions.
func keyValueMap(section capmodel.ProofSection) map[string]string {
	out := make(map[string]string)
	for _, el := range section.Elements {
		if el.KeyValue == nil {
			continue
		}
		for _, row := range el.KeyValue.Rows {
			out[row.Key] = row.Value
		}
	}
	return out
}

func TestGCPPublicResources(t *testing.T) {
	fixture := testutil.NewGCPFixture(t, "gcp/recon/list")
	fixture.Setup()

	mod, ok := plugin.Get(plugin.PlatformGCP, plugin.CategoryRecon, "public-resources")
	if !ok {
		t.Fatal("gcp public-resources module not registered")
	}

	projectID := fixture.Output("project_id")

	cfg := plugin.Config{
		Args: map[string]any{
			"project-id": []string{projectID},
			"resource-type": []string{
				"storage.googleapis.com/Bucket",
				"compute.googleapis.com/Instance",
				"sqladmin.googleapis.com/Instance",
				"cloudfunctions.googleapis.com/Function",
				"run.googleapis.com/Service",
				"compute.googleapis.com/Address",
				"compute.googleapis.com/GlobalAddress",
				"compute.googleapis.com/ForwardingRule",
			},
		},
		Context: context.Background(),
	}

	p1 := pipeline.From(cfg)
	p2 := pipeline.New[model.AurelianModel]()
	pipeline.Pipe(p1, mod.Run, p2)

	var resources []output.GCPResource
	var risks []capmodel.Risk
	for m := range p2.Range() {
		switch v := m.(type) {
		case output.GCPResource:
			resources = append(resources, v)
		case capmodel.Risk:
			risks = append(risks, v)
		}
	}
	require.NoError(t, p2.Wait())
	require.NotEmpty(t, risks, "should emit at least one risk for public resources")

	t.Run("risk fields are populated", func(t *testing.T) {
		for _, risk := range risks {
			assert.NotEmpty(t, risk.Name, "risk Name must be set")
			assert.Equal(t, "aurelian", risk.Source)
			assert.Contains(t, []string{"TH", "TM"}, risk.Status,
				"unexpected risk status: %s", risk.Status)
			assert.NotEmpty(t, risk.TargetName, "risk TargetName must be set")
			assert.NotEmpty(t, risk.Proof, "risk Proof must be set")
		}
	})

	t.Run("risk context contains expected fields", func(t *testing.T) {
		for _, risk := range risks {
			proof := decodeProof(t, risk)
			assert.Equal(t, "v1.0.0", proof.Format)
			resource := keyValueMap(sectionByTitle(t, proof, "Resource"))
			assert.NotEmpty(t, resource["Resource Type"])
			assert.NotEmpty(t, resource["Resource ID"])
			assert.NotEmpty(t, resource["GCP Project"])
			exposure := keyValueMap(sectionByTitle(t, proof, "Exposure"))
			assert.Contains(t, exposure, "Public Network")
			assert.Contains(t, exposure, "Anonymous Access")
		}
	})

	t.Run("buckets have no risk without enricher", func(t *testing.T) {
		// No bucket enricher exists yet, so buckets don't get AnonymousAccess set
		// and BucketLister doesn't set IPs/URLs — no risk is generated.
		publicBucket := fixture.Output("public_bucket_name")
		privateBucket := fixture.Output("private_bucket_name")
		assert.Falsef(t, hasRiskForNamedResource(resources, risks, publicBucket),
			"public bucket %q should not have risk (no bucket enricher)", publicBucket)
		assert.Falsef(t, hasRiskForNamedResource(resources, risks, privateBucket),
			"private bucket %q should not have risk", privateBucket)
	})

	t.Run("detects public compute instance", func(t *testing.T) {
		instanceName := fixture.Output("instance_name")
		assert.Truef(t, hasRiskForNamedResource(resources, risks, instanceName),
			"expected risk for compute instance %q with external IP", instanceName)
	})

	t.Run("detects public sql instance", func(t *testing.T) {
		sqlName := fixture.Output("sql_instance_name")
		assert.Truef(t, hasRiskForNamedResource(resources, risks, sqlName),
			"expected risk for SQL instance %q with public IP", sqlName)
	})

	t.Run("detects public cloud function", func(t *testing.T) {
		functionName := fixture.Output("function_name")
		assert.Truef(t, hasRiskForNamedResource(resources, risks, functionName),
			"expected risk for cloud function %q with allUsers invoker", functionName)
	})

	t.Run("detects public cloud run services", func(t *testing.T) {
		publicRunName := fixture.Output("cloud_run_public_name")
		privateRunName := fixture.Output("cloud_run_private_name")

		// Public Cloud Run (allUsers invoker) should be HIGH severity (public + anonymous).
		assert.Truef(t, hasRiskForNamedResource(resources, risks, publicRunName),
			"expected risk for public cloud run service %q", publicRunName)

		// Private Cloud Run still gets a public URL from GCP, so it's flagged as
		// "public-gcp-resource" (MEDIUM). Both should have risks, but status differs.
		publicRisk := findRiskForNamedResource(resources, risks, publicRunName)
		privateRisk := findRiskForNamedResource(resources, risks, privateRunName)
		if publicRisk != nil && privateRisk != nil {
			assert.Equal(t, "TH", publicRisk.Status,
				"public cloud run with allUsers should be HIGH")
			assert.Equal(t, "TM", privateRisk.Status,
				"private cloud run (URL only) should be MEDIUM")
		}
	})

	t.Run("detects public addresses", func(t *testing.T) {
		globalAddr := fixture.Output("global_address_name")
		regionalAddr := fixture.Output("regional_address_name")

		assert.Truef(t, hasRiskForNamedResource(resources, risks, globalAddr),
			"expected risk for global address %q", globalAddr)
		assert.Truef(t, hasRiskForNamedResource(resources, risks, regionalAddr),
			"expected risk for regional address %q", regionalAddr)
	})

	t.Run("private compute instance has no risk", func(t *testing.T) {
		privateInstance := fixture.Output("private_instance_name")
		assert.Falsef(t, hasRiskForNamedResource(resources, risks, privateInstance),
			"private compute instance %q should NOT have a risk", privateInstance)
	})

	t.Run("risk names follow gcp naming convention", func(t *testing.T) {
		validNames := map[string]bool{
			"public-anonymous-gcp-resource": true,
			"anonymous-gcp-resource":        true,
			"public-gcp-resource":           true,
		}
		for _, risk := range risks {
			assert.Truef(t, validNames[risk.Name],
				"unexpected risk name %q", risk.Name)
		}
	})
}

// hasRiskForNamedResource finds a resource by display name, then checks if
// there's a matching risk by TargetName. This handles resources whose
// ResourceID is a numeric ID rather than a name.
func hasRiskForNamedResource(resources []output.GCPResource, risks []capmodel.Risk, name string) bool {
	return findRiskForNamedResource(resources, risks, name) != nil
}

func findRiskForNamedResource(resources []output.GCPResource, risks []capmodel.Risk, name string) *capmodel.Risk {
	for _, r := range resources {
		if containsName(r, name) {
			for i, risk := range risks {
				if risk.TargetName == r.ResourceID {
					return &risks[i]
				}
			}
			return nil
		}
	}
	return nil
}
