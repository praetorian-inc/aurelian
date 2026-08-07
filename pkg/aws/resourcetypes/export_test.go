package resourcetypes

import "sync"

// ResetForTest invalidates the process-lifetime union cache. Tests that mutate
// the plugin registry (e.g., via plugin.ResetRegistry()) must call this before
// re-invoking GetAll/IsValid/Validate, otherwise they will observe stale data.
//
// Visible only to test binaries because this file is _test.go.
func ResetForTest() {
	allOnce = sync.Once{}
	allCache = nil
	allSet = nil
}

// ExclusionsForTest returns the keys of the exclusions map. Visible only to
// test binaries; lets external test packages iterate exclusions without
// hardcoding a knownExclusions literal that drifts when contributors add new
// entries.
func ExclusionsForTest() []string {
	out := make([]string, 0, len(exclusions))
	for rt := range exclusions {
		out = append(out, rt)
	}
	return out
}

// GlobalServicesForTest returns a copy of the region-scope ledger from
// scope.go, keyed by service segment with the justification as the value.
// Visible only to test binaries; lets external test packages enumerate the
// ledger — for dead-entry and drift checks — and assert its justifications
// without exporting the map itself.
//
// It returns the map rather than just the keys because the justification check
// (TestScope_AllEntriesJustified) must live alongside the drift guard in the
// external coverage_test.go, where the registry is populated; a keys-only
// accessor would force a second exported helper for the values.
func GlobalServicesForTest() map[string]string {
	out := make(map[string]string, len(globalServices))
	for svc, justification := range globalServices {
		out[svc] = justification
	}
	return out
}
