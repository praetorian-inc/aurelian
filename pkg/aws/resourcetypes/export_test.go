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
