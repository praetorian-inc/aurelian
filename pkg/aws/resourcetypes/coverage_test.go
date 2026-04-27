// Package resourcetypes_test is an external test package that imports the
// module loader so the plugin registry is fully populated before tests run.
// Tests here observe the runtime resource-type union; static-data tests live
// in types_test.go (internal package).
package resourcetypes_test

import (
	"regexp"
	"testing"

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
			if all[rt] || resourcetypes.IsExcluded(rt) {
				continue
			}
			t.Errorf("module %q declares %q which is not in GetAll() and not excluded",
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
		if !all[rt] {
			t.Errorf("summary type %q is not in GetAll()", rt)
		}
	}
}

func TestIsValid_ConsumerType(t *testing.T) {
	if !resourcetypes.IsValid("AWS::EC2::Instance") {
		t.Error("expected AWS::EC2::Instance to be valid (declared by find-secrets and public-resources)")
	}
}

func TestValidate_AcceptsConsumerTypes(t *testing.T) {
	err := resourcetypes.Validate([]string{"AWS::EC2::Instance", "AWS::S3::Bucket"})
	if err != nil {
		t.Errorf("expected no error for valid consumer types, got: %v", err)
	}
}

func TestGetAll_FormatValid(t *testing.T) {
	re := regexp.MustCompile(`^AWS::[A-Z][A-Za-z0-9]*::[A-Z][A-Za-z0-9]*$`)
	for _, rt := range resourcetypes.GetAll() {
		if !re.MatchString(rt) {
			t.Errorf("GetAll returned malformed type %q", rt)
		}
	}
}

func TestGetAll_SortedAndDeduped(t *testing.T) {
	all := resourcetypes.GetAll()

	seen := make(map[string]bool, len(all))
	for i, rt := range all {
		if seen[rt] {
			t.Errorf("duplicate type in GetAll(): %q", rt)
		}
		seen[rt] = true

		if i > 0 && all[i-1] >= rt {
			t.Errorf("GetAll() not sorted: %q >= %q at index %d", all[i-1], rt, i)
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
	if second[0] != original {
		t.Errorf("GetAll() leaked internal cache; mutation persisted (got %q, want %q)", second[0], original)
	}
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
		if !referenced[rt] {
			t.Errorf("exclusion %q is not declared by any module or in GetAll(); delete the dead exclusion", rt)
		}
	}
}

func TestResetForTest_AllowsRecomputation(t *testing.T) {
	// Force the cache to populate.
	first := resourcetypes.GetAll()
	if len(first) == 0 {
		t.Fatal("expected non-empty GetAll on first call")
	}

	// Reset and re-fetch — must not panic and must return a valid slice.
	resourcetypes.ResetForTest()
	second := resourcetypes.GetAll()
	if len(second) == 0 {
		t.Fatal("expected non-empty GetAll after ResetForTest")
	}

	// The post-reset slice should match the pre-reset slice byte-for-byte
	// because no module/exclusion state changed between the two calls.
	if len(first) != len(second) {
		t.Fatalf("post-reset GetAll length differs: before=%d after=%d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Errorf("index %d differs: before=%q after=%q", i, first[i], second[i])
		}
	}
}
