package resourcetypes

import (
	"maps"
	"sync"
)

// ResetForTest invalidates the process-lifetime union cache. Tests that mutate
// the plugin registry (e.g., via plugin.ResetRegistry()) must call this before
// re-invoking GetAll/IsValid/Validate, otherwise they will observe stale data.
func ResetForTest() {
	allOnce = sync.Once{}
	allCache = nil
	allSet = nil
}

// ExclusionsForTest returns the keys of the exclusions map, so external test
// packages need no knownExclusions literal that drifts as entries are added.
func ExclusionsForTest() []string {
	out := make([]string, 0, len(exclusions))
	for rt := range exclusions {
		out = append(out, rt)
	}
	return out
}

// GlobalServicesForTest returns a copy of the region-scope ledger from scope.go
// (service segment -> justification). Copied because globalServices is a
// package-level var IsGlobal reads on every call: handing out the map itself
// would let any test mutate it for every other test in the binary.
func GlobalServicesForTest() map[string]string {
	return maps.Clone(globalServices)
}
