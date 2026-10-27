package recon

import (
	"context"
	"fmt"
	"reflect"
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
// returns whatever the module sent downstream. The seam is the only way to exercise
// Run here: helpers' region listers and its config loader are all unexported inside
// package helpers, so without it a test would have to reach live AWS.
func runModule(t *testing.T, stub func(ctx context.Context, profile, profileDir string) ([]string, output.RegionSource, error)) ([]model.AurelianModel, error) {
	t.Helper()

	// The seam is silently defaultable — Run falls back to the real helper on nil — so
	// a missing stub reaches live AWS rather than failing.
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

// The EXACT set is asserted, not merely that "regions" and "concurrency" are absent:
// an absence-only assertion would let a future credential-shaped parameter — an access
// key, a role ARN, a session token — be added silently, which is the class of
// regression this guard exists to catch.
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

// --- Metadata

func TestAWSRegionsModule_Metadata(t *testing.T) {
	m := &AWSRegionsModule{}

	assert.Equal(t, "regions", m.ID())
	assert.Equal(t, plugin.PlatformAWS, m.Platform())
	assert.Equal(t, plugin.CategoryRecon, m.Category())
	assert.NotEmpty(t, m.Name())
	assert.NotEmpty(t, m.Description())
	assert.Equal(t, "moderate", m.OpsecLevel())
	assert.NotEmpty(t, m.Authors())

	// Pins the exact Guard dispatch key; the value is not an enumeration claim.
	assert.Equal(t, []string{"AWS::Organizations::Account"}, m.SupportedResourceTypes(),
		"regions must declare the Organizations::Account dispatch key so Guard's "+
			"aws_factory gate can dispatch it; see SupportedResourceTypes' doc comment")

	require.NotEmpty(t, m.References())
	for _, ref := range m.References() {
		assert.Regexp(t, `^https://`, ref, "references must be resolvable https URLs")
	}

	// A copy here would leave the bind layer populating a throwaway and Run seeing
	// zero values.
	assert.Same(t, &m.RegionsConfig, m.Parameters(),
		"Parameters() must return a pointer to the module's own RegionsConfig so "+
			"bound values reach Run")
}

// --- Output shape and provenance

// The module REPORTS the provenance the resolver determined and never re-derives it;
// the tier is known where it happens, on the resolution ladder.
//
// The fixture is DELIBERATELY UNEQUAL to helpers.Regions, so an implementation that
// inferred provenance by comparing against the compiled-in list could not produce the
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

// The inverse fixture: an account that genuinely enabled every region returns a list
// EQUAL to the compiled-in one, which a comparison-based implementation would stamp
// "static-fallback" — a stale guess for the one account whose answer was fully
// authoritative.
//
// Both orderings exist because that comparison has two spellings, and helpers.Regions
// is unsorted while Run sorts before emitting: the UNSORTED fixture catches a compare
// against helpers.Regions as-is, the PRE-SORTED one a compare against a sorted copy,
// which the unsorted fixture alone would let pass. Neither sub-case is redundant; do
// not drop one.
func TestAWSRegionsModule_Run_AuthoritativeSourceSurvivesCoincidence(t *testing.T) {
	// These preconditions guard the sub-cases, not the code: an empty or
	// already-sorted static list would collapse the two below into one and silently
	// retire the coverage the sorted case exists to add.
	require.NotEmpty(t, helpers.Regions,
		"precondition: the static list is non-empty, so the coincidence is real")

	sorted := append([]string(nil), helpers.Regions...)
	sort.Strings(sorted)
	require.NotEqual(t, helpers.Regions, sorted,
		"precondition: the static list is not already sorted, so sort() is observable")

	cases := []struct {
		name    string
		fixture []string
	}{
		{"unsorted compiled-in list", append([]string(nil), helpers.Regions...)},
		{"pre-sorted compiled-in list", append([]string(nil), sorted...)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			items, err := runModule(t, func(context.Context, string, string) ([]string, output.RegionSource, error) {
				return tc.fixture, output.SourceAccountAPI, nil
			})
			require.NoError(t, err)

			got := sole(t, items)
			assert.Equal(t, output.SourceAccountAPI, got.Source,
				"a list that coincidentally equals the compiled-in region list must still report "+
					"the source the resolver determined; stamping it static-fallback would report a "+
					"stale guess for an account whose answer was fully authoritative")

			// Order-sensitive: a length check would accept a drop plus a duplicate.
			assert.Equal(t, sorted, got.Regions,
				"the emitted list must be exactly the resolver's list, sorted")
		})
	}
}

func TestAWSRegionsModule_Run_StaticFallbackReachesOutput(t *testing.T) {
	items, err := runModule(t, staticStub("us-east-1", "eu-central-1"))
	require.NoError(t, err)

	got := sole(t, items)
	assert.Equal(t, output.SourceStaticFallback, got.Source)
	assert.Equal(t, "static-fallback", string(got.Source),
		"the wire value is a contract Guard matches on; renaming it is a breaking change")
}

// Count and len(Regions) are separate JSON fields a consumer may trust either of, so a
// disagreement between them is invisible to any test that checks just one.
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

// The input is deliberately reverse-ordered, so the assertion cannot pass by accident
// on input that was already sorted.
func TestAWSRegionsModule_Run_SortsOutput(t *testing.T) {
	unsorted := []string{"us-west-2", "ap-south-1", "eu-west-1", "af-south-1"}

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

// Run sorts, and at tier 3 the resolver's result originates from the package-level
// helpers.Regions, so sorting in place would permanently reorder a process-global. The
// helper clones today, but Run must not depend on that staying true.
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

// The emitted Regions must not alias the slice the resolver handed back — at tier 3
// that memory is the process-global helpers.Regions.
//
// Asserted against the resolver's OWN backing array rather than by comparing two runs:
// two runs allocate independent slices, so a cross-run assertion would hold no matter
// what the code did.
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

// --- Error propagation

// A resolution error must surface as an error and emit NOTHING.
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

// --- Seam integrity

// Guards the seam itself: enabledRegions is a test affordance, and a registered
// instance carrying a stub would make the shipped binary report fabricated regions.
//
// Deliberately absent: an assertion that (&AWSRegionsModule{}).enabledRegions is nil.
// The Go spec guarantees an unset func field in a composite literal is nil, so no edit
// to production code could turn that red — it constrains the compiler, not this
// module. Do not re-add it.
func TestAWSRegionsModule_RegisteredInstanceUsesRealHelper(t *testing.T) {
	for _, m := range plugin.ByPlatform(plugin.PlatformAWS) {
		if m.ID() != "regions" {
			continue
		}

		// plugin.Register wraps every module, so the registry hands back the wrapper
		// and it must be unwrapped one layer before asserting on our own type.
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

// Pins the other half of the seam: that the default BINDING is the real helper, not
// merely that the field is nil. Unlike a nil-field assertion this one is falsifiable —
// delete or invert the nil branch in resolver() and it goes red.
//
// The returned func is deliberately never called (that would mean a live AWS call), and
// Go funcs are not comparable with ==, so identity goes through reflect.Value.Pointer.
func TestAWSRegionsModule_ResolverDefaultsToRealHelper(t *testing.T) {
	got := reflect.ValueOf((&AWSRegionsModule{}).resolver()).Pointer()
	want := reflect.ValueOf(helpers.EnabledRegionsWithSource).Pointer()

	assert.Equal(t, want, got,
		"resolver() must return helpers.EnabledRegionsWithSource when the "+
			"enabledRegions seam is unset; a module that defaulted elsewhere would "+
			"resolve regions from something other than the real ladder")
}

// A set seam must win over the default, or the stub every other test in this file
// relies on would be silently ignored.
func TestAWSRegionsModule_ResolverPrefersSeamWhenSet(t *testing.T) {
	stub := func(ctx context.Context, profile, profileDir string) ([]string, output.RegionSource, error) {
		return nil, output.SourceEC2API, nil
	}

	m := &AWSRegionsModule{enabledRegions: stub}

	assert.Equal(t, reflect.ValueOf(stub).Pointer(),
		reflect.ValueOf(m.resolver()).Pointer(),
		"a set enabledRegions seam must be returned in preference to the helper")
	assert.NotEqual(t, reflect.ValueOf(helpers.EnabledRegionsWithSource).Pointer(),
		reflect.ValueOf(m.resolver()).Pointer(),
		"a set seam must not fall through to the real helper")
}
