//go:build integration

package fixture

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// registry holds fixtures that had Setup() complete successfully during
// this test binary's execution. Keyed by StateKey so fixtures shared by
// multiple tests collapse to one entry.
//
// The registry is process-scoped, which matches the per-package execution
// model of `go test`: each package is its own binary, so the registry
// never crosses package boundaries.
type registry struct {
	mu    sync.Mutex
	items map[string]*BaseFixture

	// teardownFn overrides the default teardown behavior; set in tests.
	teardownFn func(context.Context, *BaseFixture) error
}

var globalRegistry = &registry{}

// register adds a fixture to the registry. First writer for a given
// StateKey wins; subsequent registrations of the same key are no-ops.
func (r *registry) register(f *BaseFixture) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.items == nil {
		r.items = map[string]*BaseFixture{}
	}

	if _, exists := r.items[f.cfg.StateKey]; exists {
		return
	}
	r.items[f.cfg.StateKey] = f
}

// snapshot returns the registered fixtures. The underlying map is
// copied so callers may iterate without holding the registry lock.
func (r *registry) snapshot() []*BaseFixture {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]*BaseFixture, 0, len(r.items))
	for _, f := range r.items {
		out = append(out, f)
	}
	return out
}

const perFixtureDestroyTimeout = 10 * time.Minute

// DestroyAll tears down every registered fixture and sweeps its S3
// prefix. Failures are collected and returned as a single aggregated
// error so that one bad fixture does not prevent others from being
// cleaned up.
func (r *registry) DestroyAll(ctx context.Context) error {
	fixtures := r.snapshot()
	if len(fixtures) == 0 {
		return nil
	}

	fn := r.teardownFn
	if fn == nil {
		fn = defaultTeardown
	}

	var errs []error
	for _, f := range fixtures {
		fixtureCtx, cancel := context.WithTimeout(ctx, perFixtureDestroyTimeout)
		if err := fn(fixtureCtx, f); err != nil {
			errs = append(errs, fmt.Errorf("destroy %s: %w", f.cfg.StateKey, err))
		}
		cancel()
	}

	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

// defaultTeardown is the production teardown path: destroy terraform
// resources then sweep the whole module prefix in S3.
func defaultTeardown(ctx context.Context, f *BaseFixture) error {
	if err := f.teardownStack(ctx); err != nil {
		return err
	}
	if err := f.ops.PurgeModulePrefix(ctx); err != nil {
		return fmt.Errorf("purge module prefix: %w", err)
	}
	return nil
}
