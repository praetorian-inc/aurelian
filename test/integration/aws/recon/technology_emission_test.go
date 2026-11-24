//go:build integration

package recon

import (
	"context"
	"slices"
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

const (
	ecsType    = "AWS::ECS::TaskDefinition"
	lambdaType = "AWS::Lambda::Function"
)

// technologyCase pairs a fixture resource with the CPE set it must emit. Both
// sides are read from Terraform outputs: the identifier so the test can find
// the resource in a live scan, and the expectation so that the expected CPEs
// stay hand-written HCL literals rather than anything computed from
// software.Detect. A test that derived them from the code under test would
// compare the system to itself and pass regardless of what it emitted.
type technologyCase struct {
	name         string
	resourceType string
	idOutput     string
	expectOutput string
	why          string
}

var technologyCases = []technologyCase{
	{
		name:         "ECS/vendor-correctness controls",
		resourceType: ecsType,
		idOutput:     "taskdef_controls_family",
		expectOutput: "expected_controls_cpes",
		why:          "nginx:1.25.3 resolves to the live vendor f5; alpine:3.19 emits nothing",
	},
	{
		name:         "ECS/reference parsing",
		resourceType: ecsType,
		idOutput:     "taskdef_parsing_family",
		expectOutput: "expected_parsing_cpes",
		why:          "registry-qualified name, product name != image name, variant-suffixed tag; a digest-only reference the tag cannot name but the image config can",
	},
	{
		name:         "ECS/sibling distributions",
		resourceType: ecsType,
		idOutput:     "taskdef_siblings_family",
		expectOutput: "expected_siblings_cpes",
		why:          "redis:6.2.6 cannot choose between two live vendors and emits both",
	},
	{
		name:         "Lambda/java21",
		resourceType: lambdaType,
		idOutput:     "lambda_java_name",
		expectOutput: "expected_lambda_java_cpes",
		why:          "Runtime is absent from ListResources, so a non-empty set is also the proof that hydrateIfMissing fired",
	},
	{
		name:         "Lambda/ruby3.2",
		resourceType: lambdaType,
		idOutput:     "lambda_ruby_name",
		expectOutput: "expected_lambda_ruby_cpes",
		why:          "the runtime table is not java-only",
	},
	{
		name:         "Lambda/dotnet8",
		resourceType: lambdaType,
		idOutput:     "lambda_dotnet_name",
		expectOutput: "expected_lambda_dotnet_cpes",
		why:          "a CPE product name containing a dot still satisfies guard's key regex",
	},
	{
		name:         "Lambda/python3.12",
		resourceType: lambdaType,
		idOutput:     "lambda_python_name",
		expectOutput: "expected_lambda_python_cpes",
		why:          "several live vendors for a minor-only version is undecidable; rule 3 drops it",
	},
	{
		name:         "Lambda/nodejs20.x",
		resourceType: lambdaType,
		idOutput:     "lambda_node_name",
		expectOutput: "expected_lambda_node_cpes",
		why:          `"20.x" is not a resolvable version`,
	},
}

// TestTechnologyEmission deploys real AWS resources and asserts that the CPEs
// aurelian emits for each are exactly the set the fixture declares.
//
// Scope is list-all. find-secrets emits only risks — no AWSResource leaves the
// module and it runs no enrichers — so it has no Technologies to assert today;
// that is phase 3 (content inspection and ECR), which lands independently.
func TestTechnologyEmission(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/technology-emission")
	fixture.Setup()

	regions := fixture.OutputList("test_regions")
	require.NotEmpty(t, regions, "fixture must declare at least one region")

	// One scan per resource type, shared across every case for that type.
	// Scanning once per case would multiply AWS calls for no added coverage.
	scans := map[string][]model.AurelianModel{}
	for _, rt := range []string{ecsType, lambdaType} {
		scans[rt] = listAll(t, rt, regions)
		t.Logf("%s: %d results", rt, len(scans[rt]))
	}

	for _, tc := range technologyCases {
		t.Run(tc.name, func(t *testing.T) {
			identifier := fixture.Output(tc.idOutput)
			expected := fixture.OutputList(tc.expectOutput)

			res := findResource(t, scans[tc.resourceType], identifier)
			require.NotNil(t, res, "fixture resource %q not found among %d %s results",
				identifier, len(scans[tc.resourceType]), tc.resourceType)

			assert.ElementsMatch(t, expected, cpesOf(*res),
				"%s emitted the wrong CPE set — %s", identifier, tc.why)
		})
	}

	t.Run("no forbidden vendor appears anywhere in the scan", func(t *testing.T) {
		forbidden := fixture.OutputList("forbidden_cpe_substrings")
		require.NotEmpty(t, forbidden, "fixture must declare forbidden substrings")

		checked := 0
		for _, results := range scans {
			for _, r := range results {
				res, ok := r.(output.AWSResource)
				if !ok {
					continue
				}
				for _, cpe := range cpesOf(res) {
					checked++
					for _, bad := range forbidden {
						assert.NotContains(t, cpe, bad,
							"resource %s emitted CPE %q containing forbidden substring %q",
							res.ResourceID, cpe, bad)
					}
				}
			}
		}
		require.NotZero(t, checked, "no CPEs were emitted at all; the check is vacuous")
		t.Logf("checked %d emitted CPEs against %d forbidden substrings", checked, len(forbidden))
	})

	t.Run("every emitted CPE carries the observed version verbatim", func(t *testing.T) {
		// The invariant that replaced most of forbidden_cpe_substrings.
		//
		// Vendor breadth is harmless — a vendor that never shipped the
		// observed version matches no CVE — but a rewritten VERSION is not: it
		// attributes CVEs that do not apply to what is actually running. An
		// earlier revision truncated versions to find a CPE dictionary entry,
		// and measured against the live NVD CVE corpus that fabricated 19 CVE
		// attributions across 30 observations.
		checked := 0
		for _, results := range scans {
			for _, r := range results {
				res, ok := r.(output.AWSResource)
				if !ok {
					continue
				}
				for _, tech := range res.Technologies {
					parts := strings.Split(tech.CPE, ":")
					require.Greater(t, len(parts), 5, "malformed CPE %q", tech.CPE)
					version := parts[5]
					checked++
					assert.Contains(t, tech.Evidence, version,
						"resource %s emitted version %q which does not appear in its own evidence %q — the observed version was rewritten",
						res.ResourceID, version, tech.Evidence)
				}
			}
		}
		require.NotZero(t, checked, "no CPEs were emitted at all; the check is vacuous")
	})

	t.Run("every emitted CPE satisfies guard's Technology key regex", func(t *testing.T) {
		// Guard rejects a Technology whose key does not match
		// ^#technology#cpe:2\.3(:[^:]+){11}$, dropping the node silently. A CPE
		// well-formed here but not there is invisible in production, so the
		// shape is asserted against real scan output and not only fixtures.
		checked := 0
		for _, results := range scans {
			for _, r := range results {
				res, ok := r.(output.AWSResource)
				if !ok {
					continue
				}
				for _, tech := range res.Technologies {
					checked++
					assert.Regexp(t, `^cpe:2\.3(:[^:]+){11}$`, tech.CPE,
						"resource %s emitted a CPE guard would reject", res.ResourceID)
					assert.NotEmpty(t, tech.Source, "technology on %s has no Source", res.ResourceID)
					assert.NotEmpty(t, tech.Evidence, "technology on %s has no Evidence", res.ResourceID)
				}
			}
		}
		require.NotZero(t, checked, "no CPEs were emitted at all; the check is vacuous")
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
	slices.Sort(out)
	return out
}
