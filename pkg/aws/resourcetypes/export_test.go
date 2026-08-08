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
// Visible only to test binaries; it lets external test packages enumerate the
// ledger — for the dead-entry and drift checks, which need the registry
// populated — without exporting the map itself.
//
// The copy, not the return type, is what protects the ledger: globalServices is
// a package-level var that IsGlobal reads on every call, so handing out the map
// would let any test mutate it for every other test in the binary. That holds
// whether callers read the values or only the keys.
func GlobalServicesForTest() map[string]string {
	out := make(map[string]string, len(globalServices))
	for svc, justification := range globalServices {
		out[svc] = justification
	}
	return out
}
