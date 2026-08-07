package recon

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	helpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// runModule drives AWSRegionsModule.Run with the enabledRegions seam stubbed, and
// returns whatever the module sent downstream.
//
// The seam is the only way to exercise Run in this package: helpers'
// AccountRegionLister/EC2RegionLister and its config loader are all unexported
// inside package helpers, so without it a test here would have to reach live AWS.
// Stubbing at this boundary still exercises everything the module itself owns —
// the clone, the sort, the Count/Regions construction, and the provenance
// pass-through — while making zero network calls.
func runModule(t *testing.T, stub func(ctx context.Context, profile, profileDir string) ([]string, output.RegionSource, error)) ([]model.AurelianModel, error) {
	t.Helper()

	// The seam is silently defaultable: Run falls back to the real helper when
	// enabledRegions is nil. A test that reached here with a nil stub would make a
	// LIVE AWS call — failing confusingly on a bare machine and, far worse, PASSING
	// for the wrong reason on a credentialed one. Refuse it loudly instead of
	// letting a hollow green through.
	require.NotNil(t, stub,
		"runModule requires an explicit stub; a nil seam makes Run call live AWS and "+
			"can pass for the wrong reason on a credentialed machine")

	m := &AWSRegionsModule{enabledRegions: stub}

	out := pipeline.New[model.AurelianModel]()
	var runErr error
	go func() {
		defer out.Close()
		runErr = m.Run(plugin.Config{Context: context.Background()}, out)
	}()

	items, err := out.Collect()
	require.NoError(t, err, "pipeline collect must not fail")
	return items, runErr
}

// sole unwraps the single AWSEnabledRegions the module is contracted to emit.
func sole(t *testing.T, items []model.AurelianModel) *output.AWSEnabledRegions {
	t.Helper()

	require.Len(t, items, 1, "the module must emit exactly one result")
	got, ok := items[0].(*output.AWSEnabledRegions)
	require.True(t, ok, "expected *output.AWSEnabledRegions, got %T", items[0])
	return got
}

// staticStub reports the given regions as tier 3.
func staticStub(regions ...string) func(context.Context, string, string) ([]string, output.RegionSource, error) {
	return func(context.Context, string, string) ([]string, output.RegionSource, error) {
		return regions, output.SourceStaticFallback, nil
	}
}

// ---------------------------------------------------------------------------
// SAC-11 — parameter surface
// ---------------------------------------------------------------------------

// TestRegionsConfig_ParameterSurfaceIsExact is the standing guard that turns the
// C-1/C-2 credential clearances into an invariant.
//
// It asserts the EXACT set, not merely that "regions" and "concurrency" are
// absent. An absence-only assertion would let a future credential-shaped
// parameter — an access key, a role ARN, a session token — be added silently,
// which is the whole class of regression this guard exists to catch. Exact-set
// means any addition fails CI by name and forces a deliberate review.
//
// Concretely this pins RegionsConfig to embedding AWSReconBase and NOT
// AWSCommonRecon: the latter carries regions/concurrency/resource-type/
// resource-arn, and a "regions" parameter would make the module that ANSWERS
// "which regions are enabled" take the answer as input.
func TestRegionsConfig_ParameterSurfaceIsExact(t *testing.T) {
	params, err := plugin.ParametersFrom(&RegionsConfig{})
	require.NoError(t, err)

	names := make([]string, 0, len(params))
	for _, p := range params {
		names = append(names, p.Name)
	}

	assert.ElementsMatch(t,
		[]string{"output-dir", "profile", "profile-dir", "opsec_level"},
		names,
		"RegionsConfig's parameter surface changed. If a parameter was ADDED, confirm it "+
			"carries no credential material and is genuinely needed, then update this list "+
			"deliberately. If the embed was switched to AWSCommonRecon, revert it: that adds "+
			"a `regions` parameter, making the module that answers \"which regions are "+
			"enabled\" take the answer as input.")
}

// The module must expose no parameter that could carry credential material.
// Named separately from the exact-set assertion so a failure reports WHY the
// surface is constrained, not merely that it drifted.
func TestRegionsConfig_NoCredentialShapedParameters(t *testing.T) {
	params, err := plugin.ParametersFrom(&RegionsConfig{})
	require.NoError(t, err)

	forbidden := []string{"key", "secret", "token", "password", "credential", "session"}
	for _, p := range params {
		for _, bad := range forbidden {
			assert.NotContains(t, p.Name, bad,
				"parameter %q looks credential-shaped; the region coordinator resolves "+
					"credentials through the shared profile chain and must never accept "+
					"identity material directly", p.Name)
		}
		assert.False(t, p.Sensitive,
			"parameter %q is marked Sensitive, which means it carries material this "+
				"module should not be accepting at all", p.Name)
	}
}

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

func TestAWSRegionsModule_Metadata(t *testing.T) {
	m := &AWSRegionsModule{}

	assert.Equal(t, "regions", m.ID())
	assert.Equal(t, plugin.PlatformAWS, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.NotEmpty(t, m.Name())
	assert.NotEmpty(t, m.Description())
	assert.NotEmpty(t, m.OpsecLevel())
	assert.NotEmpty(t, m.Authors())

	// The module reads no resource types: it answers a question ABOUT the account
	// rather than enumerating resources. A non-nil value here would put it in
	// resourcetypes' consumer-coverage drift test for types it never touches.
	assert.Nil(t, m.SupportedResourceTypes(),
		"regions enumerates no resource types; see TestModuleConsumerCoverage")

	require.NotEmpty(t, m.References())
	for _, ref := range m.References() {
		assert.Regexp(t, `^https://`, ref, "references must be resolvable https URLs")
	}

	// Parameters must hand back a pointer into the module's own config, otherwise
	// the bind layer populates a throwaway copy and Run sees zero values.
	assert.Same(t, &m.RegionsConfig, m.Parameters(),
		"Parameters() must return a pointer to the module's own RegionsConfig so "+
			"bound values reach Run")
}

// ---------------------------------------------------------------------------
// Output shape and provenance
// ---------------------------------------------------------------------------

// TestAWSRegionsModule_Run_PropagatesSourceVerbatim is the module's core contract:
// it REPORTS the provenance the helper determined and never re-derives it.
//
// The tier is known where it happens, on the resolution ladder. A module that
// inferred provenance by comparing the result against the compiled-in list would
// be wrong in both directions: an account whose genuinely-enabled regions happen
// to equal the static list would be mislabelled a fallback, and a stale static
// list that drifted would be mislabelled authoritative.
//
// The static-fallback case is asserted with a region list DELIBERATELY UNEQUAL to
// helpers.Regions, so a comparison-based implementation could not produce the
// right answer by coincidence.
func TestAWSRegionsModule_Run_PropagatesSourceVerbatim(t *testing.T) {
	for _, source := range []output.RegionSource{
		output.SourceAccountAPI,
		output.SourceEC2API,
		output.SourceStaticFallback,
	} {
		t.Run(string(source), func(t *testing.T) {
			stub := func(context.Context, string, string) ([]string, output.RegionSource, error) {
				return []string{"eu-west-1", "ap-south-1"}, source, nil
			}

			items, err := runModule(t, stub)
			require.NoError(t, err)

			assert.Equal(t, source, sole(t, items).Source,
				"the module must pass the helper's source through unchanged, never "+
					"re-derive it by comparing against the static list")
		})
	}
}

// TestAWSRegionsModule_Run_AuthoritativeSourceSurvivesCoincidence is the
// adversarial half of the passthrough contract, and the case a naive test misses.
//
// An account that has genuinely enabled every region returns a list EQUAL to the
// compiled-in 31. A comparison-based implementation would look at that list, see it
// match helpers.Regions, and stamp it "static-fallback" — reporting a stale guess
// for the one account whose answer was fully authoritative. The operator then
// distrusts correct inventory.
//
// This is the inverse of the unequal-list case above: together they close both
// directions, so no comparison-based implementation can pass by coincidence.
func TestAWSRegionsModule_Run_AuthoritativeSourceSurvivesCoincidence(t *testing.T) {
	// Precondition: the fixture really is the static list, so the coincidence this
	// test describes is actually being exercised.
	coincident := append([]string(nil), helpers.Regions...)
	require.ElementsMatch(t, helpers.Regions, coincident,
		"precondition: the fixture must equal the compiled-in list")

	items, err := runModule(t, func(context.Context, string, string) ([]string, output.RegionSource, error) {
		return coincident, output.SourceAccountAPI, nil
	})
	require.NoError(t, err)

	got := sole(t, items)
	assert.Equal(t, output.SourceAccountAPI, got.Source,
		"a list that coincidentally equals the compiled-in region list must still report "+
			"the source the resolver determined; stamping it static-fallback would report a "+
			"stale guess for an account whose answer was fully authoritative")
	assert.Len(t, got.Regions, len(helpers.Regions))
}

// TestAWSRegionsModule_Run_StaticFallbackReachesOutput pins the tier-3 wire value
// specifically, since Guard matches on this exact string.
func TestAWSRegionsModule_Run_StaticFallbackReachesOutput(t *testing.T) {
	items, err := runModule(t, staticStub("us-east-1", "eu-central-1"))
	require.NoError(t, err)

	got := sole(t, items)
	assert.Equal(t, output.SourceStaticFallback, got.Source)
	assert.Equal(t, "static-fallback", string(got.Source),
		"the wire value is a contract Guard matches on; renaming it is a breaking change")
}

// TestAWSRegionsModule_Run_CountMatchesRegions pins Count against len(Regions).
//
// The two are separate JSON fields, so a consumer may trust either. They can only
// disagree through a bug, and a disagreement is invisible to any test that checks
// just one of them.
func TestAWSRegionsModule_Run_CountMatchesRegions(t *testing.T) {
	tests := []struct {
		name    string
		regions []string
	}{
		{"single region", []string{"us-east-1"}},
		{"several regions", []string{"us-east-1", "eu-west-1", "ap-south-1"}},
		{"empty region list", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			items, err := runModule(t, staticStub(tt.regions...))
			require.NoError(t, err)

			got := sole(t, items)
			assert.Len(t, got.Regions, got.Count,
				"Count and len(Regions) are independent JSON fields and must never disagree")
			assert.Equal(t, len(tt.regions), got.Count)
			assert.ElementsMatch(t, tt.regions, got.Regions,
				"the module must report the regions it was given, no additions or drops")
		})
	}
}

// TestAWSRegionsModule_Run_SortsOutput covers the sort with a deliberately
// reverse-ordered input, so the assertion cannot pass by accident on input that
// was already sorted.
func TestAWSRegionsModule_Run_SortsOutput(t *testing.T) {
	unsorted := []string{"us-west-2", "ap-south-1", "eu-west-1", "af-south-1"}

	// Precondition: the input really is out of order, so sorting is observable.
	require.False(t, sort.StringsAreSorted(unsorted),
		"precondition: the fixture must be unsorted for this test to mean anything")

	items, err := runModule(t, staticStub(unsorted...))
	require.NoError(t, err)

	got := sole(t, items)
	assert.True(t, sort.StringsAreSorted(got.Regions),
		"the module must emit a sorted region list")
	assert.Equal(t,
		[]string{"af-south-1", "ap-south-1", "eu-west-1", "us-west-2"},
		got.Regions)
}

// TestAWSRegionsModule_Run_DoesNotMutateCallerSlice pins the clone in Run.
//
// Run sorts, and at tier 3 the helper's result originates from the package-level
// helpers.Regions variable that AWSCommonRecon.PostBind reads on list-all's live
// bind path. Sorting in place would permanently reorder a process-global. The
// helper clones today, but Run must not depend on that staying true, so this test
// hands it a slice it owns and proves Run left it alone.
func TestAWSRegionsModule_Run_DoesNotMutateCallerSlice(t *testing.T) {
	caller := []string{"us-west-2", "ap-south-1", "eu-west-1"}
	original := append([]string(nil), caller...)

	items, err := runModule(t, func(context.Context, string, string) ([]string, output.RegionSource, error) {
		return caller, output.SourceAccountAPI, nil
	})
	require.NoError(t, err)

	require.Equal(t, original, caller,
		"Run sorted the slice it was handed; it must clone before sorting, because at "+
			"tier 3 that slice can be the process-global helpers.Regions")

	// And the emitted list is still correctly sorted despite the clone.
	assert.True(t, sort.StringsAreSorted(sole(t, items).Regions))
}

// The emitted Regions must not alias the slice the resolver handed back, so a
// downstream consumer writing through it cannot reach the resolver's memory — which
// at tier 3 is the process-global helpers.Regions.
//
// This asserts against the resolver's OWN backing array rather than comparing two
// separate runs: two runs allocate independent slices, so a cross-run assertion
// would hold no matter what the code did.
func TestAWSRegionsModule_Run_OutputDoesNotAliasResolverSlice(t *testing.T) {
	backing := []string{"us-east-1", "eu-west-1"}
	original := append([]string(nil), backing...)

	items, err := runModule(t, func(context.Context, string, string) ([]string, output.RegionSource, error) {
		return backing, output.SourceAccountAPI, nil
	})
	require.NoError(t, err)

	got := sole(t, items)
	require.NotEmpty(t, got.Regions)

	got.Regions[0] = "MUTATED"

	assert.Equal(t, original, backing,
		"writing through the emitted Regions reached the resolver's slice; at tier 3 "+
			"that slice can be the process-global helpers.Regions")
	assert.NotContains(t, backing, "MUTATED")
}

// ---------------------------------------------------------------------------
// Error propagation
// ---------------------------------------------------------------------------

// A resolution error must surface as an error and emit NOTHING. Emitting a
// zero-value result alongside an error would put an empty region list into
// inventory, which a consumer cannot distinguish from "this account has no
// regions enabled".
func TestAWSRegionsModule_Run_ResolutionErrorEmitsNothing(t *testing.T) {
	items, err := runModule(t, func(context.Context, string, string) ([]string, output.RegionSource, error) {
		return nil, "", fmt.Errorf("no credentials configured")
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "no credentials configured", "the cause must be preserved")
	assert.Contains(t, err.Error(), "regions:", "the error must name the module for operator triage")
	assert.Empty(t, items,
		"a failed resolution must emit no result; an empty region list in inventory is "+
			"indistinguishable from an account with no regions enabled")
}

// ---------------------------------------------------------------------------
// Seam integrity
// ---------------------------------------------------------------------------

// TestAWSRegionsModule_RegisteredInstanceUsesRealHelper guards the seam itself.
//
// enabledRegions is a test affordance. If the instance registered in init() ever
// carried a non-nil stub, the shipped binary would silently report fabricated
// regions — a far worse failure than the one the seam exists to make testable.
// Nil here means Run falls through to helpers.EnabledRegionsWithSource.
func TestAWSRegionsModule_RegisteredInstanceUsesRealHelper(t *testing.T) {
	assert.Nil(t, (&AWSRegionsModule{}).enabledRegions,
		"a freshly constructed module must leave the seam nil so Run uses the real "+
			"helper; only tests may set it")

	for _, m := range plugin.ByPlatform(plugin.PlatformAWS) {
		if m.ID() != "regions" {
			continue
		}

		// plugin.Register wraps every module in &ModuleWrapper{Module: m}
		// (registry.go:41), so the registry hands back the wrapper, never the
		// concrete module. Unwrap one layer before asserting on our own type.
		wrapper, ok := m.(*plugin.ModuleWrapper)
		require.True(t, ok, "expected the registry to hand back a *plugin.ModuleWrapper, got %T", m)

		mod, ok := wrapper.Module.(*AWSRegionsModule)
		require.True(t, ok, "the registered \"regions\" module changed type, got %T", wrapper.Module)

		assert.Nil(t, mod.enabledRegions,
			"the REGISTERED module instance has a stubbed enabledRegions seam; the "+
				"shipped binary would report fabricated regions")
		return
	}

	require.Fail(t, "module \"regions\" is not registered for platform AWS")
}
