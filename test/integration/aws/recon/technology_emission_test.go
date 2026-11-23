//go:build integration

package recon

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/model"
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/enrichers" // register enrichers
	_ "github.com/praetorian-inc/aurelian/pkg/modules/aws/recon"     // register modules
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTechnologyEmission deploys two real resources and asserts that the CPEs
// aurelian emits for them are exactly the ones the fixture declares.
//
// The expected CPE strings live in the fixture's outputs.tf as hand-written
// literals, never computed from software.Detect — comparing the pipeline's
// output against the decoder's own output would prove nothing.
//
// Each resource carries a matched positive and negative control, so the test
// distinguishes correct resolution from a decoder that emits for everything:
//
//	ECS task definition  nginx:1.25.3  -> cpe:2.3:a:f5:nginx:1.25.3:*:...
//	                     alpine:3.19   -> nothing
//	Lambda               java21        -> cpe:2.3:a:oracle:openjdk:21:*:...
//	                     python3.12    -> nothing
func TestTechnologyEmission(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/technology-emission")
	fixture.Setup()

	regions := fixture.OutputList("test_regions")
	require.NotEmpty(t, regions, "fixture must declare at least one region")

	t.Run("ECS task definition emits the live vendor for a versioned image", func(t *testing.T) {
		results := listAll(t, "AWS::ECS::TaskDefinition", regions)

		family := fixture.Output("taskdef_family")
		res := findResource(t, results, family)
		require.NotNil(t, res, "fixture task definition %s not found in %d results", family, len(results))

		assert.ElementsMatch(t, fixture.OutputList("expected_taskdef_cpes"), cpesOf(*res),
			"task definition %s emitted the wrong CPE set", family)

		// The second container (alpine:3.19) contributes nothing, so the set
		// above is already the whole assertion for it. Stated explicitly so a
		// regression reads as a failure rather than as an extra element.
		for _, cpe := range cpesOf(*res) {
			assert.NotContains(t, cpe, "alpine",
				"alpine:3.19 is an OS base image and must not resolve to the alpine email client")
		}
	})

	t.Run("Lambda emits for a resolvable runtime and nothing for an undecidable one", func(t *testing.T) {
		results := listAll(t, "AWS::Lambda::Function", regions)

		resolvable := fixture.Output("lambda_resolvable_name")
		res := findResource(t, results, resolvable)
		require.NotNil(t, res, "fixture function %s not found in %d results", resolvable, len(results))

		// Runtime is absent from the ListResources payload, so a non-empty
		// result here is also the only end-to-end proof that the enricher's
		// hydrateIfMissing call fired.
		assert.ElementsMatch(t, fixture.OutputList("expected_lambda_cpes"), cpesOf(*res),
			"function %s emitted the wrong CPE set; an empty set means hydration did not fire", resolvable)

		undecidable := fixture.Output("lambda_undecidable_name")
		other := findResource(t, results, undecidable)
		require.NotNil(t, other, "fixture function %s not found in %d results", undecidable, len(results))
		assert.Empty(t, cpesOf(*other),
			"python3.12 is version-undecidable across several vendors and must emit nothing")
	})

	t.Run("no forbidden vendor appears anywhere in the scan", func(t *testing.T) {
		forbidden := fixture.OutputList("forbidden_cpe_substrings")
		require.NotEmpty(t, forbidden, "fixture must declare forbidden substrings")

		var all []string
		for _, rt := range []string{"AWS::ECS::TaskDefinition", "AWS::Lambda::Function"} {
			for _, r := range listAll(t, rt, regions) {
				res, ok := r.(output.AWSResource)
				if !ok {
					continue
				}
				all = append(all, cpesOf(res)...)
			}
		}

		for _, cpe := range all {
			for _, bad := range forbidden {
				assert.NotContains(t, cpe, bad,
					"emitted CPE %q contains forbidden substring %q", cpe, bad)
			}
		}
		t.Logf("checked %d emitted CPEs against %d forbidden substrings", len(all), len(forbidden))
	})

	t.Run("every emitted CPE satisfies guard's Technology key regex", func(t *testing.T) {
		// Guard rejects a Technology whose key does not match
		// ^#technology#cpe:2\.3(:[^:]+){11}$, dropping the node silently. A CPE
		// that is well-formed here but not there is invisible in production, so
		// the shape is asserted against real scan output rather than fixtures.
		for _, rt := range []string{"AWS::ECS::TaskDefinition", "AWS::Lambda::Function"} {
			for _, r := range listAll(t, rt, regions) {
				res, ok := r.(output.AWSResource)
				if !ok {
					continue
				}
				for _, tech := range res.Technologies {
					assert.Regexp(t, `^cpe:2\.3(:[^:]+){11}$`, tech.CPE,
						"resource %s emitted a CPE guard would reject", res.ResourceID)
					assert.NotEmpty(t, tech.Source, "technology on %s has no Source", res.ResourceID)
					assert.NotEmpty(t, tech.Evidence, "technology on %s has no Evidence", res.ResourceID)
				}
			}
		}
	})
}

// listAll runs the list-all module for one resource type across the given
// regions and returns everything it emitted.
func listAll(t *testing.T, resourceType string, regions []string) []model.AurelianModel {
	t.Helper()

	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "list-all")
	require.True(t, ok, "list-all module not registered")

	results, err := testutil.RunAndCollect(t, mod, plugin.Config{
		Args: map[string]any{
			"resource-type": []string{resourceType},
			"regions":       regions,
			"scan-type":     "full",
		},
		Context: context.Background(),
	})
	require.NoError(t, err, "list-all failed for %s", resourceType)
	return results
}

// findResource returns the single AWSResource whose identity contains needle,
// or nil. It fails the test if more than one matches, since an ambiguous match
// would make the CPE assertions meaningless.
func findResource(t *testing.T, results []model.AurelianModel, needle string) *output.AWSResource {
	t.Helper()

	var found []output.AWSResource
	for _, r := range results {
		res, ok := r.(output.AWSResource)
		if !ok {
			continue
		}
		if strings.Contains(res.ResourceID, needle) || strings.Contains(res.ARN, needle) {
			found = append(found, res)
		}
	}

	switch len(found) {
	case 0:
		return nil
	case 1:
		return &found[0]
	default:
		t.Fatalf("%q matched %d resources; expected exactly one", needle, len(found))
		return nil
	}
}

// cpesOf returns the resource's emitted CPE strings, sorted for stable
// comparison and failure output.
func cpesOf(r output.AWSResource) []string {
	out := make([]string, 0, len(r.Technologies))
	for _, tech := range r.Technologies {
		out = append(out, tech.CPE)
	}
	sort.Strings(out)
	return out
}
