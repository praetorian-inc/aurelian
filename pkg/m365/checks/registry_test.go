package checks

import (
	"context"
	"sync"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/m365/databag"
)

func TestRegisterAndGet(t *testing.T) {
	// Clear registry for isolated test
	mu.Lock()
	saved := registry
	registry = make(map[string]CheckFunc)
	mu.Unlock()
	defer func() {
		mu.Lock()
		registry = saved
		mu.Unlock()
	}()

	called := false
	Register("test.1", func(_ context.Context, _ *databag.M365DataBag) (*CheckResult, error) {
		called = true
		return &CheckResult{Passed: true, Message: "test passed"}, nil
	})

	fn, ok := Get("test.1")
	if !ok {
		t.Fatal("expected to find registered check")
	}

	result, err := fn(context.Background(), &databag.M365DataBag{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatal("check function was not called")
	}
	if !result.Passed {
		t.Fatal("expected check to pass")
	}
}

func TestGetMissing(t *testing.T) {
	_, ok := Get("nonexistent.check.id")
	if ok {
		t.Fatal("expected Get to return false for unregistered check")
	}
}

func TestRegisterDuplicate(t *testing.T) {
	mu.Lock()
	saved := registry
	registry = make(map[string]CheckFunc)
	mu.Unlock()
	defer func() {
		mu.Lock()
		registry = saved
		mu.Unlock()
	}()

	noop := func(_ context.Context, _ *databag.M365DataBag) (*CheckResult, error) {
		return &CheckResult{Passed: true}, nil
	}

	Register("dup.1", noop)

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on duplicate registration")
		}
	}()
	Register("dup.1", noop)
}

func TestRegisteredIDs(t *testing.T) {
	mu.Lock()
	saved := registry
	registry = make(map[string]CheckFunc)
	mu.Unlock()
	defer func() {
		mu.Lock()
		registry = saved
		mu.Unlock()
	}()

	noop := func(_ context.Context, _ *databag.M365DataBag) (*CheckResult, error) {
		return &CheckResult{Passed: true}, nil
	}

	Register("a.1", noop)
	Register("b.2", noop)

	ids := RegisteredIDs()
	if len(ids) != 2 {
		t.Fatalf("expected 2 IDs, got %d", len(ids))
	}
}

func TestConcurrentGet(t *testing.T) {
	mu.Lock()
	saved := registry
	registry = make(map[string]CheckFunc)
	mu.Unlock()
	defer func() {
		mu.Lock()
		registry = saved
		mu.Unlock()
	}()

	noop := func(_ context.Context, _ *databag.M365DataBag) (*CheckResult, error) {
		return &CheckResult{Passed: true, Message: "concurrent"}, nil
	}

	Register("conc.1", noop)
	Register("conc.2", noop)
	Register("conc.3", noop)

	// Run many concurrent Get() calls to verify thread safety
	var wg sync.WaitGroup
	const goroutines = 100

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			ids := []string{"conc.1", "conc.2", "conc.3", "nonexistent"}
			id := ids[n%len(ids)]
			fn, ok := Get(id)
			if id == "nonexistent" {
				if ok {
					t.Errorf("expected Get(%q) to return false", id)
				}
			} else {
				if !ok {
					t.Errorf("expected Get(%q) to return true", id)
				}
				if fn == nil {
					t.Errorf("expected Get(%q) to return non-nil function", id)
				}
			}
		}(i)
	}

	wg.Wait()
}

func TestRegisteredIDsNotEmpty(t *testing.T) {
	// In production with init() registrations, IDs should be populated.
	// However, since other tests may swap the registry, we test by
	// registering entries in an isolated registry and verifying.
	mu.Lock()
	saved := registry
	registry = make(map[string]CheckFunc)
	mu.Unlock()
	defer func() {
		mu.Lock()
		registry = saved
		mu.Unlock()
	}()

	noop := func(_ context.Context, _ *databag.M365DataBag) (*CheckResult, error) {
		return &CheckResult{Passed: true}, nil
	}

	Register("prod.1", noop)
	Register("prod.2", noop)
	Register("prod.3", noop)

	ids := RegisteredIDs()
	if len(ids) == 0 {
		t.Fatal("RegisteredIDs() should not return empty when checks are registered")
	}
	if len(ids) != 3 {
		t.Fatalf("expected 3 IDs, got %d", len(ids))
	}

	// Verify each registered ID is retrievable
	for _, id := range ids {
		fn, ok := Get(id)
		if !ok {
			t.Errorf("registered ID %q not retrievable via Get()", id)
		}
		if fn == nil {
			t.Errorf("registered ID %q returned nil function", id)
		}
	}
}

func TestGetReturnsNilForEmpty(t *testing.T) {
	fn, ok := Get("")
	if ok {
		t.Error("Get(\"\") should return false for empty string key")
	}
	if fn != nil {
		t.Error("Get(\"\") should return nil function for empty string key")
	}
}

func TestRegisterNilFunc(t *testing.T) {
	mu.Lock()
	saved := registry
	registry = make(map[string]CheckFunc)
	mu.Unlock()
	defer func() {
		mu.Lock()
		registry = saved
		mu.Unlock()
	}()

	// Register allows nil functions (no validation in Register).
	// Get should return ok=true but fn=nil.
	Register("nil-func.1", nil)

	fn, ok := Get("nil-func.1")
	if !ok {
		t.Fatal("expected Get to return true for registered nil function")
	}
	if fn != nil {
		t.Error("expected Get to return nil function when nil was registered")
	}
}
