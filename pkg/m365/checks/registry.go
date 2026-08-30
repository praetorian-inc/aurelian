// Package checks provides a registry for M365 CIS check functions.
// Each check evaluates a specific CIS benchmark requirement against
// pre-fetched data in the M365DataBag.
package checks

import (
	"context"
	"fmt"
	"sync"

	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
)

// CheckFunc is the signature for a CIS check evaluation function.
// It reads from the DataBag and returns a CheckResult.
type CheckFunc func(ctx context.Context, bag *databag.M365DataBag) (*CheckResult, error)

// CheckResult holds the outcome of a single CIS check.
type CheckResult struct {
	Passed     bool
	ResourceID string         // tenant ID, policy ID, mailbox ID, etc.
	Evidence   map[string]any // raw data for evidence generation
	Message    string         // human-readable PASS/FAIL explanation
}

var (
	mu       sync.RWMutex
	registry = make(map[string]CheckFunc)
)

// Register adds a check function to the registry keyed by CIS ID (e.g. "5.2.2.1").
func Register(cisID string, fn CheckFunc) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[cisID]; exists {
		panic(fmt.Sprintf("m365 check %q already registered", cisID))
	}
	registry[cisID] = fn
}

// Get retrieves a registered check function by CIS ID.
func Get(cisID string) (CheckFunc, bool) {
	mu.RLock()
	defer mu.RUnlock()
	fn, ok := registry[cisID]
	return fn, ok
}

// RegisteredIDs returns all registered CIS check IDs.
func RegisteredIDs() []string {
	mu.RLock()
	defer mu.RUnlock()
	ids := make([]string, 0, len(registry))
	for id := range registry {
		ids = append(ids, id)
	}
	return ids
}
