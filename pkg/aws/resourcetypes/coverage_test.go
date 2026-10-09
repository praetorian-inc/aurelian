// Package resourcetypes_test blank-imports the module loader so the plugin
// registry is populated: tests here observe the runtime union, while
// static-data tests live in types_test.go (internal package).
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

// Every type a registered AWS module declares must be in GetAll() or excluded.
// On failure: add the type to baseline if list-all should enumerate it, or to
// exclusions with a justification if not.
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

// Region-scope partition (LAB-5615 Phase A). These tests need the loader's blank
// import, which cannot sit in package resourcetypes: the loader blank-imports
// recon and recon imports resourcetypes, so that import would close a cycle.

// serviceOf extracts the <Service> segment of an AWS::<Service>::<Resource> type.
// It only derives the observed service namespace; the classification itself is
// exercised through GetGlobal/GetRegional, never re-implemented here.
func serviceOf(t *testing.T, rt string) string {
	t.Helper()
	parts := strings.Split(rt, "::")
	require.Len(t, parts, 3, "resource type %q is not AWS::Service::Resource", rt)
	return parts[1]
}

// reviewedRegionalServices is the drift guard's allow-list: services in the
// GetAll() union deliberately classified as REGIONAL. Hand-maintained on purpose —
// a derived set would absorb a newly registered service silently. Adding an entry
// asserts you checked its control plane; if it is global, add it to the scope
// ledger in scope.go with a justification instead.
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
	"ECR":                    {},
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

// The sentinel guarding every other test in this group. AWS::Route53::HostedZone
// is declared ONLY by a consumer module and is absent from baseline, so it is in
// GetAll() if and only if the blank loader import above survives. Strip that
// import and the registry goes empty, GetAll() collapses to baseline, and every
// partition test below keeps passing while silently observing a fraction of the
// real type set. Do not delete this test, and do not "fix" it by adding
// Route53::HostedZone to baseline — that would defeat the detection.
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

// Covers the accessor guarantees GetGlobal and GetRegional advertise: the two
// halves account for every type in GetAll(), each preserves GetAll()'s sort
// order, and neither aliases the union cache.
//
// The count is tied STRUCTURALLY below, never as literals. Do not re-add
// assert.Len(t, global, 7) / assert.Len(t, regional, 42): a regional count fires
// on legitimate additions whose only remedy is bumping the number, training
// exactly the reflex that makes the next real drift invisible.
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

// Pins that the regions module's Guard dispatch key stays invisible to list-all:
// the exclusions map lists the type and ensureComputed's exclusion-deletion loop
// removes it before allCache is built. If this fails the fix is to restore the
// exclusion, NOT to stop declaring the dispatch key.
func TestRegionsModule_DeclarationDoesNotLeakIntoUnion(t *testing.T) {
	const dispatchKey = "AWS::Organizations::Account"

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

	// Organizations IS a global service, so had the key reached allCache it would
	// have landed in GetGlobal and broken this set. Restating the set here makes
	// the coupling explicit at the point of risk.
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

// Pins a deliberate non-entry in the scope ledger. The name invites a contributor
// to "fix the obvious omission" by adding GlobalAccelerator to it, but its control
// plane is pinned to us-west-2 where the genuinely-global services resolve to
// us-east-1: classifying it global would route it to a shard where it answers
// nothing, silently dropping every accelerator from inventory — a total loss no
// partition or count test could detect.
func TestGetRegional_KeepsGlobalAccelerator(t *testing.T) {
	assert.Contains(t, resourcetypes.GetRegional(), "AWS::GlobalAccelerator::Accelerator",
		"GlobalAccelerator must stay REGIONAL: its control plane pins us-west-2, not "+
			"us-east-1, so classifying it global routes it to a shard where it answers "+
			"nowhere and silently drops all accelerators from inventory")
}

// Pins the second deliberate non-entry. S3 is often called global, but
// listBucketsInRegion filters server-side on the BucketRegion it sets on
// s3.ListBucketsInput to avoid CloudControl's duplicate enumeration; classifying
// S3 global would bypass that per-region filter.
func TestGetRegional_KeepsS3Bucket(t *testing.T) {
	assert.Contains(t, resourcetypes.GetRegional(), "AWS::S3::Bucket",
		"S3 must stay REGIONAL: listBucketsInRegion filters server-side on the "+
			"BucketRegion it sets on s3.ListBucketsInput to avoid CloudControl duplicate enumeration")
}

// A ledger entry for a service no type actually uses is dead weight from a past
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

// The drift guard. Every service in the GetAll() union must be explicitly
// classified — global (scope.go's ledger) or reviewed-regional (above) — so a
// newly registered service fails HERE, by name, rather than being silently
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

// Asserts no service is classified BOTH global and reviewed-regional — the guard
// TestScope_ReviewedServiceLedger structurally cannot be, because it builds the
// two ledgers' UNION and union is idempotent: a service listed twice is one
// member, both its inclusions still hold, and the overlap is exactly the
// information it discards. That direction is silent — adding an already-global
// service to reviewedRegionalServices touches test-only data, so the union,
// GetGlobal() and GetRegional() are unchanged and every other test stays green
// while the allow-list now asserts a global control plane is region-scoped.
func TestScope_LedgersAreDisjoint(t *testing.T) {
	for svc := range resourcetypes.GlobalServicesForTest() {
		_, alsoRegional := reviewedRegionalServices[svc]
		assert.False(t, alsoRegional,
			"service %q is in BOTH scope ledgers: globalServices in scope.go and "+
				"reviewedRegionalServices in this file. It cannot be both, and listing it "+
				"in reviewedRegionalServices asserts its control plane is region-scoped. "+
				"Delete %q from whichever ledger is wrong: from reviewedRegionalServices "+
				"if it is genuinely global, from globalServices if it is not.", svc, svc)
	}
}

// Covers the T001 acceptance criteria for the predicate itself: it keys on the
// SERVICE segment, and malformed input returns false rather than panicking. The
// last three fixtures keep the ledger service "IAM" in parts[1], so they redden
// if the prefix and resource-segment checks are dropped from IsGlobal.
//
// There is deliberately NO empty-service fixture ("AWS::::Role"): "" is not a key
// in globalServices either, so no such fixture can redden — it would read as
// covering a segment check while discriminating against nothing.
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

// Empty-registry degradation. The sentinel above guards THIS binary; it says
// nothing about a consumer in another Go module, which never had the import to
// strip. Guard is exactly such a consumer, and for it an empty registry is a
// reachable state rather than a bug — so what the union does there is behaviour.

// warnRecorder captures slog records so a test can assert what was logged and at
// which level. Enabled always reports true so the handler can never itself be the
// reason a record is missing. It deliberately duplicates the similar recorder in
// internal/helpers/aws rather than adding a shared non-test import to the tree.
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
// of the test and restores the previous one afterwards, captured BEFORE SetDefault
// so nested or successive captures still restore the right logger.
//
// Callers must not call t.Parallel(): this swaps the process-global default slog
// logger, so parallel callers would capture each other's records and restore the
// wrong logger on cleanup.
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
// Saving and restoring the plugin.Registry pointer instead brings the populated
// registry back whole, with nothing re-registered.
//
// The union cache is reset on both edges because it is process-lifetime and does
// not observe registry changes on its own. The cleanup re-asserts the sentinel
// type so a restore that silently failed reddens HERE, by name, instead of in
// some unrelated test that happens to run next.
//
// Callers must not call t.Parallel(): this reassigns the process-global
// plugin.Registry and resets the process-lifetime union cache, so a parallel
// caller would observe the emptied registry staged for this test.
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

// Pins what an out-of-module consumer sees when it reaches this package without
// blank-importing pkg/modules/loader. A truncated union is indistinguishable from
// a good one at the call site, so the Warn is the only signal — demoting it to
// Debug or deleting it is a regression no assertion on the returned value can
// catch. IsGlobal is pure and does NOT degrade with it.
func TestEmptyRegistry_UnionCollapsesToBaselineAndWarns(t *testing.T) {
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

// The negative control for the Warn above: without it that assertion would pass
// just as well against a union build that warned unconditionally, which trains
// operators to ignore the line and defeats it as thoroughly as silence would.
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
