// Package resourcetypes_test is an external test package that imports the
// module loader so the plugin registry is fully populated before tests run.
// Tests here observe the runtime resource-type union; static-data tests live
// in types_test.go (internal package).
package resourcetypes_test

import (
	"context"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/aurelian/pkg/aws/resourcetypes"
	"github.com/praetorian-inc/aurelian/pkg/plugin"

	// Blank-import the loader to register all modules before tests run.
	_ "github.com/praetorian-inc/aurelian/pkg/modules/loader"
)

// TestModuleConsumerCoverage is the headline drift test: every type a
// registered AWS module declares in SupportedResourceTypes() must be in
// GetAll() or in the exclusions list. Failing this test means a consumer
// module added a type that list-all won't enumerate — fix by either adding
// the type to baseline (if listing makes sense) or to exclusions (with
// justification).
func TestModuleConsumerCoverage(t *testing.T) {
	all := make(map[string]bool)
	for _, rt := range resourcetypes.GetAll() {
		all[rt] = true
	}

	for _, m := range plugin.ByPlatform(plugin.PlatformAWS) {
		for _, rt := range m.SupportedResourceTypes() {
			assert.True(t, all[rt] || resourcetypes.IsExcluded(rt),
				"module %q declares %q which is not in GetAll() and not excluded",
				m.ID(), rt)
		}
	}
}

func TestSummary_SubsetOfGetAll(t *testing.T) {
	all := make(map[string]bool)
	for _, rt := range resourcetypes.GetAll() {
		all[rt] = true
	}

	for _, rt := range resourcetypes.GetSummary() {
		assert.True(t, all[rt], "summary type %q is not in GetAll()", rt)
	}
}

func TestIsValid_ConsumerType(t *testing.T) {
	assert.True(t, resourcetypes.IsValid("AWS::EC2::Instance"),
		"expected AWS::EC2::Instance to be valid (declared by find-secrets and public-resources)")
}

func TestValidate_AcceptsConsumerTypes(t *testing.T) {
	err := resourcetypes.Validate([]string{"AWS::EC2::Instance", "AWS::S3::Bucket"})
	assert.NoError(t, err, "expected no error for valid consumer types")
}

func TestGetAll_FormatValid(t *testing.T) {
	re := regexp.MustCompile(`^AWS::[A-Z][A-Za-z0-9]*::[A-Z][A-Za-z0-9]*$`)
	for _, rt := range resourcetypes.GetAll() {
		assert.True(t, re.MatchString(rt), "GetAll returned malformed type %q", rt)
	}
}

func TestGetAll_SortedAndDeduped(t *testing.T) {
	all := resourcetypes.GetAll()

	seen := make(map[string]bool, len(all))
	for i, rt := range all {
		assert.False(t, seen[rt], "duplicate type in GetAll(): %q", rt)
		seen[rt] = true

		if i > 0 {
			assert.Less(t, all[i-1], rt,
				"GetAll() not sorted: %q >= %q at index %d", all[i-1], rt, i)
		}
	}
}

func TestGetAll_DefensiveCopy(t *testing.T) {
	first := resourcetypes.GetAll()
	if len(first) == 0 {
		t.Skip("GetAll() returned empty slice")
	}
	original := first[0]
	first[0] = "MUTATED"

	second := resourcetypes.GetAll()
	assert.Equal(t, original, second[0],
		"GetAll() leaked internal cache; mutation persisted")
}

func TestExclusions_AreReferenced(t *testing.T) {
	// Every exclusion must be a type that some baseline entry or registered
	// consumer module declares. If an exclusion has no referrer, it's dead
	// weight from a past refactor — delete it.
	referenced := make(map[string]bool)

	for _, rt := range resourcetypes.GetAll() {
		referenced[rt] = true
	}
	for _, m := range plugin.ByPlatform(plugin.PlatformAWS) {
		for _, rt := range m.SupportedResourceTypes() {
			referenced[rt] = true
		}
	}

	for _, rt := range resourcetypes.ExclusionsForTest() {
		assert.True(t, referenced[rt],
			"exclusion %q is not declared by any module or in GetAll(); delete the dead exclusion", rt)
	}
}

// ---------------------------------------------------------------------------
// Region-scope partition (LAB-5615 Phase A).
//
// These tests live in this file because package resourcetypes cannot import the
// module loader: the loader blank-imports recon, and recon/helper.go imports
// resourcetypes, so that import would close a cycle. The blank import therefore
// has to sit in an external test package. That is a COMPILE-TIME constraint on
// where the import may go, and it is the whole reason for this file.
//
// It is NOT a claim that an internal test would observe a smaller union, and
// that distinction matters because the reverse was previously written here as
// fact. go test links package resourcetypes and package resourcetypes_test into
// a single binary, so the loader's init() has already populated the registry
// before any test in either package runs. Measured 2026-08-08: an internal probe
// calling GetAll() directly observes the same 49-entry union an external one
// does. Do not re-justify this file's location with a runtime claim about what
// GetAll() returns — that claim is false.
// ---------------------------------------------------------------------------

// serviceOf extracts the <Service> segment of an AWS::<Service>::<Resource>
// type. Used only to derive the observed service namespace from GetAll(); the
// classification itself is exercised through GetGlobal/GetRegional so these
// tests never re-implement the predicate under test.
func serviceOf(t *testing.T, rt string) string {
	t.Helper()
	parts := strings.Split(rt, "::")
	require.Len(t, parts, 3, "resource type %q is not AWS::Service::Resource", rt)
	return parts[1]
}

// reviewedRegionalServices is the drift guard's allow-list: every service in
// the GetAll() union that a human has reviewed and deliberately classified as
// REGIONAL. It is intentionally a hand-maintained literal, not a derivation —
// a derived set would absorb any newly registered service silently, which is
// precisely the failure TestScope_ReviewedServiceLedger exists to prevent.
//
// Adding a service here is an assertion that you checked its control plane and
// confirmed it is region-scoped. If it is global, add it to the scope ledger in
// scope.go with a justification instead.
var reviewedRegionalServices = map[string]struct{}{
	"Amplify":                {},
	"ApiGateway":             {},
	"ApiGatewayV2":           {},
	"AppRunner":              {},
	"AppSync":                {},
	"AutoScaling":            {},
	"CloudFormation":         {},
	"CloudWatch":             {},
	"Cognito":                {},
	"DynamoDB":               {},
	"EC2":                    {},
	"ECS":                    {},
	"EFS":                    {},
	"EKS":                    {},
	"ElasticBeanstalk":       {},
	"ElasticLoadBalancing":   {},
	"ElasticLoadBalancingV2": {},
	"Elasticsearch":          {},
	"GlobalAccelerator":      {},
	"KMS":                    {},
	"Lambda":                 {},
	"Logs":                   {},
	"OpenSearchService":      {},
	"RAM":                    {},
	"RDS":                    {},
	"Redshift":               {},
	"S3":                     {},
	"SNS":                    {},
	"SQS":                    {},
	"SSM":                    {},
	"SecretsManager":         {},
	"StepFunctions":          {},
	"Transfer":               {},
}

// TestPartition_RegistryPopulated is the sentinel guarding every other test in
// this group. AWS::Route53::HostedZone is declared ONLY by a consumer module
// (SubdomainTakeoverModule.SupportedResourceTypes in pkg/modules/aws/recon) and
// is absent from baseline, so it appears in GetAll() if and only if the blank
// loader import above is still present.
//
// WHY THIS EXISTS: if an import-tidier (goimports on a stale file, an IDE
// "remove unused imports" action, a merge that drops the line) strips that
// blank import, the registry goes empty, GetAll() collapses to baseline, and
// every partition test below would keep passing while silently observing a
// fraction of the real type set. This test fails loudly in that case instead.
// Do not delete it, and do not "fix" it by adding Route53::HostedZone to
// baseline — that would defeat the detection.
func TestPartition_RegistryPopulated(t *testing.T) {
	assert.Contains(t, resourcetypes.GetAll(), "AWS::Route53::HostedZone",
		"loader blank-import appears to have been stripped: GetAll() no longer "+
			"contains the consumer-only type AWS::Route53::HostedZone, so the "+
			"registry is not populated and every partition test in this file is vacuous")
}

func TestPartition_IsDisjoint(t *testing.T) {
	global := resourcetypes.GetGlobal()
	regional := make(map[string]bool, len(global))
	for _, rt := range resourcetypes.GetRegional() {
		regional[rt] = true
	}

	for _, rt := range global {
		assert.False(t, regional[rt],
			"resource type %q is in both GetGlobal() and GetRegional(); the partition must be disjoint", rt)
	}
}

func TestPartition_UnionEqualsGetAll(t *testing.T) {
	// GetAll() is already exclusion-filtered upstream by the exclusion-deletion
	// loop in ensureComputed, so the two halves must reconstruct it EXACTLY —
	// not "GetAll() minus exclusions".
	union := append(resourcetypes.GetGlobal(), resourcetypes.GetRegional()...)
	assert.ElementsMatch(t, resourcetypes.GetAll(), union,
		"GetGlobal() + GetRegional() must reconstruct GetAll() exactly")
}

// TestPartition_AccessorContract covers the accessor guarantees GetGlobal and
// GetRegional advertise: the two halves account for every type in GetAll(),
// each preserves GetAll()'s sort order, and neither aliases the union cache.
//
// The count guarantee is tied STRUCTURALLY below — len(global)+len(regional)
// against len(GetAll()) — never pinned as literals. Do not re-add assertions of
// the form assert.Len(t, global, 7) / assert.Len(t, regional, 42):
//
//   - They serve none of the three guarantees this test scopes itself to, and
//     the structural equality is what actually discharges the first of them.
//   - A literal global count is a strictly weaker duplicate of
//     TestGetGlobal_ExactSet, which names all seven types; nothing can redden the
//     count that does not also redden that test, and it tells you WHICH type moved.
//   - A literal regional count fires on legitimate additions, and its only
//     available remedy is to bump the number — training exactly the reflex that
//     makes the next real drift invisible. The risk it appears to guard (a type
//     under a brand-new service silently defaulting to regional) is held by
//     TestScope_ReviewedServiceLedger, which names the service.
//
// Recipe: move a single type between scopes by adding or removing its service in
// the scope ledger. The named-set tests redden and name the type that moved —
// with no count literals present.
func TestPartition_AccessorContract(t *testing.T) {
	global := resourcetypes.GetGlobal()
	regional := resourcetypes.GetRegional()

	assert.Equal(t, len(resourcetypes.GetAll()), len(global)+len(regional))

	assert.IsNonDecreasing(t, global, "GetGlobal() must preserve GetAll()'s sort order")
	assert.IsNonDecreasing(t, regional, "GetRegional() must preserve GetAll()'s sort order")

	// Neither accessor may hand out a window onto allCache.
	require.NotEmpty(t, global)
	require.NotEmpty(t, regional)
	global[0] = "MUTATED"
	regional[0] = "MUTATED"
	assert.NotEqual(t, "MUTATED", resourcetypes.GetGlobal()[0],
		"GetGlobal() leaked the union cache; a caller's mutation persisted")
	assert.NotEqual(t, "MUTATED", resourcetypes.GetRegional()[0],
		"GetRegional() leaked the union cache; a caller's mutation persisted")
	assert.NotContains(t, resourcetypes.GetAll(), "MUTATED",
		"partition accessors leaked into GetAll()")
}

// TestRegionsModule_DeclarationDoesNotLeakIntoUnion pins the inertness argument
// in AWSRegionsModule.SupportedResourceTypes' doc comment.
//
// The regions module declares AWS::Organizations::Account purely as a Guard
// dispatch key (Guard's agora.MatchesSupportedResourceType rejects a module with
// an empty list, so nil would make it undispatchable for every target). The
// declaration must stay invisible to list-all: the exclusions map lists the type
// and ensureComputed's exclusion-deletion loop removes it from the seen set
// before allCache is built from that set.
//
// This test lives HERE rather than beside the module because the generated
// loader in pkg/modules/loader blank-imports pkg/modules/aws/recon, so a test
// in package recon cannot import the loader to populate the registry. This file
// already carries that import and TestPartition_RegistryPopulated guards it.
//
// If this fails, the exclusion was dropped or the union stopped filtering — the
// fix is to restore the exclusion, NOT to stop declaring the dispatch key.
func TestRegionsModule_DeclarationDoesNotLeakIntoUnion(t *testing.T) {
	const dispatchKey = "AWS::Organizations::Account"

	// Precondition: the module really does declare it, so this test cannot pass
	// vacuously if the declaration is reverted to nil.
	declared := false
	for _, m := range plugin.ByPlatform(plugin.PlatformAWS) {
		if m.ID() == "regions" && slices.Contains(m.SupportedResourceTypes(), dispatchKey) {
			declared = true
			break
		}
	}
	require.True(t, declared,
		"precondition: the regions module must declare %q as its Guard dispatch key; "+
			"without the declaration this test proves nothing", dispatchKey)

	assert.NotContains(t, resourcetypes.GetAll(), dispatchKey,
		"the regions module's dispatch key leaked into list-all's union; it is on the "+
			"exclusion list in exclusions.go and ensureComputed's exclusion-deletion loop "+
			"must delete it before allCache is built")

	// GetGlobal/GetRegional filter allCache, so neither half can carry it either.
	assert.NotContains(t, resourcetypes.GetGlobal(), dispatchKey)
	assert.NotContains(t, resourcetypes.GetRegional(), dispatchKey)

	// Organizations IS a global service (the "Organizations" key in scope.go's
	// globalServices ledger), so had the key reached allCache it would have
	// landed in GetGlobal and broken the exact set below. Restating that set
	// here makes the coupling explicit at the point of risk.
	assert.ElementsMatch(t, []string{
		"AWS::CloudFront::Distribution",
		"AWS::IAM::Group",
		"AWS::IAM::Policy",
		"AWS::IAM::Role",
		"AWS::IAM::User",
		"AWS::Organizations::Organization",
		"AWS::Route53::HostedZone",
	}, resourcetypes.GetGlobal(),
		"GetGlobal() must still be exactly the 7 reviewed global types; note the "+
			"Organizations entry is ::Organization, a DIFFERENT type from the "+
			"::Account dispatch key")
}

func TestGetGlobal_ExactSet(t *testing.T) {
	assert.ElementsMatch(t, []string{
		"AWS::CloudFront::Distribution",
		"AWS::IAM::Group",
		"AWS::IAM::Policy",
		"AWS::IAM::Role",
		"AWS::IAM::User",
		"AWS::Organizations::Organization",
		"AWS::Route53::HostedZone",
	}, resourcetypes.GetGlobal())
}

// TestGetRegional_KeepsGlobalAccelerator pins a deliberate non-entry in the
// scope ledger.
//
// Global Accelerator is global by nature, and the name invites a contributor to
// "fix the obvious omission" by adding it to the ledger. That would be an
// inventory-losing bug: its control plane is pinned to us-west-2, whereas the
// four genuinely-global services all resolve to us-east-1. Classifying it
// global would route it to a us-east-1 global shard where it answers nothing,
// silently dropping every accelerator from inventory — a total loss that no
// partition or count test could detect. Today CloudControl's fan-out (the
// ActInRegions call in CloudControlEnumerator.EnumerateByType) reaches it in
// us-west-2 as a regional type.
func TestGetRegional_KeepsGlobalAccelerator(t *testing.T) {
	assert.Contains(t, resourcetypes.GetRegional(), "AWS::GlobalAccelerator::Accelerator",
		"GlobalAccelerator must stay REGIONAL: its control plane pins us-west-2, not "+
			"us-east-1, so classifying it global routes it to a shard where it answers "+
			"nowhere and silently drops all accelerators from inventory")
}

// TestGetRegional_KeepsS3Bucket pins the second deliberate non-entry.
//
// S3 is often called global, but listBucketsInRegion already filters
// server-side on the BucketRegion it sets on s3.ListBucketsInput, and the
// S3Enumerator doc comment records that this exists specifically to avoid the
// duplicate enumeration CloudControl causes. Classifying S3 global would bypass
// that per-region filter.
func TestGetRegional_KeepsS3Bucket(t *testing.T) {
	assert.Contains(t, resourcetypes.GetRegional(), "AWS::S3::Bucket",
		"S3 must stay REGIONAL: listBucketsInRegion filters server-side on the "+
			"BucketRegion it sets on s3.ListBucketsInput to avoid CloudControl duplicate enumeration")
}

// TestScope_NoDeadLedgerEntries mirrors TestExclusions_AreReferenced: a ledger
// entry for a service no type actually uses is dead weight from a past
// refactor and should be deleted.
func TestScope_NoDeadLedgerEntries(t *testing.T) {
	observed := make(map[string]bool)
	for _, rt := range resourcetypes.GetAll() {
		observed[serviceOf(t, rt)] = true
	}

	for svc := range resourcetypes.GlobalServicesForTest() {
		assert.True(t, observed[svc],
			"scope ledger entry %q matches no type in GetAll(); delete the dead entry", svc)
	}
}

// TestScope_ReviewedServiceLedger is the drift guard. Every service in the
// GetAll() union must be explicitly classified — either global (scope.go's
// ledger) or reviewed-regional (reviewedRegionalServices above). A newly
// registered service therefore fails HERE, by name, rather than being silently
// absorbed by the regional default and shipped unreviewed.
func TestScope_ReviewedServiceLedger(t *testing.T) {
	classified := make(map[string]bool, len(reviewedRegionalServices))
	for svc := range reviewedRegionalServices {
		classified[svc] = true
	}
	for svc := range resourcetypes.GlobalServicesForTest() {
		classified[svc] = true
	}

	observed := make(map[string]bool)
	for _, rt := range resourcetypes.GetAll() {
		observed[serviceOf(t, rt)] = true
	}

	for svc := range observed {
		assert.True(t, classified[svc],
			"AWS service %q appears in GetAll() but is not classified for region scope. "+
				"Classify it: if its control plane is global, add %q to the ledger in "+
				"pkg/aws/resourcetypes/scope.go with a justification; if it is region-scoped, "+
				"add %q to reviewedRegionalServices in this file. Do not leave it unclassified — "+
				"the regional default would ship it unreviewed.", svc, svc, svc)
	}

	for svc := range classified {
		assert.True(t, observed[svc],
			"service %q is classified but no longer appears in GetAll(); remove the stale entry", svc)
	}
}

// TestIsGlobal_TypeParsing covers the T001 acceptance criteria for the
// predicate itself: it keys on the SERVICE segment, and malformed input
// returns false rather than panicking.
//
// Recipe for the format cases: drop `|| parts[0] != "AWS" || parts[2] == ""`
// from IsGlobal, leaving the len(parts) != 3 check alone. Exactly the three
// fixtures "other::IAM::Role", "::IAM::Role", and "AWS::IAM::" redden — each
// keeps the ledger service "IAM" in parts[1], so a length-only check looks it up
// and reports true.
//
// There is deliberately NO empty-service fixture ("AWS::::Role"). It reports
// false under the length-only implementation too, because "" is not a key in
// globalServices (scope.go) — so no such fixture can redden, and one would read
// as covering a segment check while discriminating against nothing.
func TestIsGlobal_TypeParsing(t *testing.T) {
	tests := []struct {
		name string
		rt   string
		want bool
	}{
		{"global service", "AWS::IAM::Role", true},
		{"global service, other resource", "AWS::IAM::Group", true},
		{"regional service", "AWS::EC2::Instance", false},
		{"global-sounding but regional", "AWS::GlobalAccelerator::Accelerator", false},
		{"s3 is regional", "AWS::S3::Bucket", false},
		{"empty string", "", false},
		{"no separators", "garbage", false},
		{"two segments", "AWS::IAM", false},
		{"four segments", "AWS::IAM::Role::Extra", false},
		{"non-AWS prefix, real global service in service position", "other::IAM::Role", false},
		{"empty prefix, real global service in service position", "::IAM::Role", false},
		{"empty resource segment, global service", "AWS::IAM::", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				assert.Equal(t, tt.want, resourcetypes.IsGlobal(tt.rt))
			})
		})
	}
}

func TestResetForTest_AllowsRecomputation(t *testing.T) {
	// Force the cache to populate.
	first := resourcetypes.GetAll()
	require.NotEmpty(t, first, "expected non-empty GetAll on first call")

	// Reset and re-fetch — must not panic and must return a valid slice.
	resourcetypes.ResetForTest()
	second := resourcetypes.GetAll()
	require.NotEmpty(t, second, "expected non-empty GetAll after ResetForTest")

	// The post-reset slice should match the pre-reset slice byte-for-byte
	// because no module/exclusion state changed between the two calls.
	require.Len(t, second, len(first), "post-reset GetAll length differs")
	for i := range first {
		assert.Equal(t, first[i], second[i], "index %d differs", i)
	}
}

// ---------------------------------------------------------------------------
// Empty-registry degradation (the other direction from
// TestPartition_RegistryPopulated).
//
// That sentinel guards THIS binary: it fails if the loader blank-import above is
// stripped. It says nothing about a consumer in another Go module, which never
// had the import to strip. Guard is exactly such a consumer, and for it an empty
// registry is a reachable state rather than a bug — so what the union does in
// that state is behaviour, and gets pinned here.
// ---------------------------------------------------------------------------

// warnRecorder captures slog records so a test can assert what was logged and at
// which level. Enabled always reports true so the handler can never itself be the
// reason a record is missing.
//
// It is a deliberate near-duplicate of recordingHandler in
// internal/helpers/aws/aws_regions_test.go: both are unexported test helpers in
// different packages, and this one carries only the projection its two
// assertions need. Extracting a shared testutil package to save ~20 lines would
// add a non-test import path to the tree for no behavioural gain.
type warnRecorder struct {
	mu       sync.Mutex
	messages []string
}

func (h *warnRecorder) Enabled(context.Context, slog.Level) bool { return true }

func (h *warnRecorder) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if r.Level == slog.LevelWarn {
		h.messages = append(h.messages, r.Message)
	}
	return nil
}

func (h *warnRecorder) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *warnRecorder) WithGroup(string) slog.Handler      { return h }

func (h *warnRecorder) warnings() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.messages...)
}

// captureWarnings routes the default logger into a warnRecorder for the duration
// of the test and restores the previous logger afterwards. The previous logger is
// captured BEFORE SetDefault so nested or successive captures still restore the
// right one.
func captureWarnings(t *testing.T) *warnRecorder {
	t.Helper()

	h := &warnRecorder{}
	restore := slog.Default()
	slog.SetDefault(slog.New(h))
	t.Cleanup(func() { slog.SetDefault(restore) })
	return h
}

// withEmptyRegistry swaps a fresh, empty plugin registry in for the duration of
// the test and puts the real one back afterwards.
//
// plugin.ResetRegistry() on its own would be ONE-WAY — the loader's init()
// functions cannot be re-run, and plugin.Register panics on a duplicate key — so
// every later test in this binary would observe a permanently empty registry.
// The escape is that plugin.Registry is an exported package var that ResetRegistry
// simply REASSIGNS: saving the pointer and putting it back restores the populated
// registry whole, with nothing re-registered. That is what makes this test safe to
// run in the same binary as every test above, and it is why no separate
// loader-free test package is needed to reach this state.
//
// The union cache is reset on both edges, because it is process-lifetime and does
// not observe registry changes on its own. The cleanup re-asserts the sentinel
// type so a restore that silently failed reddens HERE, by name, instead of
// reddening some unrelated test that happens to run next.
func withEmptyRegistry(t *testing.T) {
	t.Helper()

	saved := plugin.Registry
	t.Cleanup(func() {
		plugin.Registry = saved
		resourcetypes.ResetForTest()
		assert.Contains(t, resourcetypes.GetAll(), "AWS::Route53::HostedZone",
			"registry restore failed: the union did not come back populated, so every "+
				"test after this one is running against a truncated type set")
	})

	plugin.ResetRegistry()
	resourcetypes.ResetForTest()
}

// TestEmptyRegistry_UnionCollapsesToBaselineAndWarns pins what an out-of-module
// consumer sees when it reaches this package without blank-importing
// pkg/modules/loader.
//
// Three things are behaviour here, none of them observable from a populated
// binary:
//
//   - The union collapses. Every consumer-declared type is gone, which is a far
//     wider loss than the four global types alone.
//   - The collapse is RECORDED. A truncated union is otherwise indistinguishable
//     from a good one at the call site, so the Warn is the only signal; demoting
//     it to Debug or deleting it is a regression no assertion on the returned
//     value can catch. Same argument, same shape, as the tier-3 fallback Warn in
//     internal/helpers/aws.
//   - IsGlobal does NOT degrade. It is pure, so it keeps classifying types the
//     truncated union no longer lists — the asymmetry the export note in scope.go
//     now documents for Guard.
func TestEmptyRegistry_UnionCollapsesToBaselineAndWarns(t *testing.T) {
	// Precondition: measure the populated union first, so a change that empties
	// the registry for every test cannot make the comparison below vacuous.
	populated := resourcetypes.GetAll()
	require.Contains(t, populated, "AWS::Route53::HostedZone",
		"precondition: the registry must start populated for this test to mean anything")

	withEmptyRegistry(t)
	h := captureWarnings(t)

	require.Empty(t, plugin.ByPlatform(plugin.PlatformAWS),
		"precondition: the registry swap did not take effect")

	truncated := resourcetypes.GetAll()
	assert.Less(t, len(truncated), len(populated),
		"an empty registry must shrink the union: got %d types, populated is %d",
		len(truncated), len(populated))
	assert.NotContains(t, truncated, "AWS::Route53::HostedZone",
		"AWS::Route53::HostedZone is declared only by a consumer module, so it "+
			"cannot survive an empty registry")

	// The exact set the reviewer's report is about: GetGlobal keeps only the
	// baseline IAM types and loses the four that reach it through modules.
	assert.ElementsMatch(t, []string{
		"AWS::IAM::Policy",
		"AWS::IAM::Role",
		"AWS::IAM::User",
	}, resourcetypes.GetGlobal(),
		"with an empty registry GetGlobal must fall to the three baseline IAM types; "+
			"CloudFront::Distribution, IAM::Group, Organizations::Organization and "+
			"Route53::HostedZone all reach it only through registered modules")

	// IsGlobal reads the ledger, not the union, so it is indifferent to all of it.
	assert.True(t, resourcetypes.IsGlobal("AWS::Route53::HostedZone"),
		"IsGlobal must stay pure: it classifies correctly even for a type the "+
			"truncated union no longer lists")

	warnings := h.warnings()
	require.Len(t, warnings, 1, "the empty-registry union build must emit exactly one Warn")
	assert.Contains(t, warnings[0], "pkg/modules/loader",
		"the Warn must name the import a consumer has to add, not just report the symptom")
}

// TestPopulatedRegistry_UnionBuildIsSilent is the negative control for the Warn
// above. Without it the assertion would pass just as well against a union build
// that warned unconditionally — which trains operators to ignore the line and
// defeats it as thoroughly as silence would.
func TestPopulatedRegistry_UnionBuildIsSilent(t *testing.T) {
	require.NotEmpty(t, plugin.ByPlatform(plugin.PlatformAWS),
		"precondition: the registry must be populated for this control to discriminate")

	h := captureWarnings(t)

	resourcetypes.ResetForTest()
	require.Contains(t, resourcetypes.GetAll(), "AWS::Route53::HostedZone",
		"precondition: the rebuild must have seen the populated registry")

	assert.Empty(t, h.warnings(),
		"a populated union build must be silent at Warn")
}
