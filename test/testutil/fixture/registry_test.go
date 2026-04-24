//go:build integration

package fixture

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/terraform-exec/tfexec"
)

func TestRegistry_RegistersFixtureByStateKey(t *testing.T) {
	r := &registry{}

	a := &BaseFixture{cfg: Config{StateKey: "integration-tests/aws/recon/one/terraform.tfstate"}}
	b := &BaseFixture{cfg: Config{StateKey: "integration-tests/aws/recon/two/terraform.tfstate"}}

	r.register(a)
	r.register(b)

	got := r.snapshot()
	if len(got) != 2 {
		t.Fatalf("want 2 entries, got %d", len(got))
	}
}

func TestRegistry_DedupesByStateKey(t *testing.T) {
	r := &registry{}

	key := "integration-tests/aws/recon/shared/terraform.tfstate"
	a := &BaseFixture{cfg: Config{StateKey: key}}
	b := &BaseFixture{cfg: Config{StateKey: key}} // different pointer, same key

	r.register(a)
	r.register(b)

	got := r.snapshot()
	if len(got) != 1 {
		t.Fatalf("want 1 deduplicated entry, got %d", len(got))
	}
	if got[0] != a {
		t.Fatalf("want first registered fixture to win")
	}
}

func TestRegistry_ConcurrentRegisterIsSafe(t *testing.T) {
	r := &registry{}
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r.register(&BaseFixture{cfg: Config{StateKey: "k"}})
		}(i)
	}
	wg.Wait()

	got := r.snapshot()
	if len(got) != 1 {
		t.Fatalf("want 1 deduplicated entry after concurrent registration, got %d", len(got))
	}
}

func TestRegistry_DestroyAll_CallsTeardownForEach(t *testing.T) {
	r := &registry{}

	var mu sync.Mutex
	var teardowns []string
	mkFixture := func(key string) *BaseFixture {
		return &BaseFixture{
			cfg: Config{StateKey: key},
			ops: &destroyRecordingOps{
				onDestroy: func() {
					mu.Lock()
					teardowns = append(teardowns, key)
					mu.Unlock()
				},
			},
		}
	}
	// Use the registry's test hook to swap teardown with a recorded no-op.
	r.teardownFn = func(ctx context.Context, f *BaseFixture) error {
		f.ops.(*destroyRecordingOps).onDestroy()
		return nil
	}

	r.register(mkFixture("a"))
	r.register(mkFixture("b"))

	if err := r.DestroyAll(context.Background()); err != nil {
		t.Fatalf("DestroyAll: %v", err)
	}
	if len(teardowns) != 2 {
		t.Fatalf("want 2 teardowns, got %d: %v", len(teardowns), teardowns)
	}
}

func TestRegistry_DestroyAll_AggregatesErrors(t *testing.T) {
	r := &registry{}
	r.teardownFn = func(ctx context.Context, f *BaseFixture) error {
		return errors.New("boom: " + f.cfg.StateKey)
	}

	r.register(&BaseFixture{cfg: Config{StateKey: "a"}})
	r.register(&BaseFixture{cfg: Config{StateKey: "b"}})

	err := r.DestroyAll(context.Background())
	if err == nil {
		t.Fatal("want aggregated error, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "boom: a") || !strings.Contains(msg, "boom: b") {
		t.Fatalf("want aggregated error to mention both failures, got: %v", msg)
	}
}

type destroyRecordingOps struct {
	baseOpsZero
	onDestroy func()
}

// baseOpsZero is a do-nothing ops impl used only to satisfy the interface
// in tests that don't care about terraform calls.
type baseOpsZero struct{}

func (baseOpsZero) GetRemoteHash(context.Context) (string, error) { return "", nil }
func (baseOpsZero) PutRemoteHash(context.Context, string) error   { return nil }
func (baseOpsZero) Init(context.Context, ...tfexec.InitOption) error {
	return nil
}
func (baseOpsZero) Destroy(context.Context, ...tfexec.DestroyOption) error {
	return nil
}
func (baseOpsZero) Apply(context.Context, ...tfexec.ApplyOption) error { return nil }
func (baseOpsZero) Output(context.Context, ...tfexec.OutputOption) (map[string]tfexec.OutputMeta, error) {
	return nil, nil
}
func (baseOpsZero) UploadArtifacts(context.Context) error   { return nil }
func (baseOpsZero) DeleteArtifacts(context.Context) error   { return nil }
func (baseOpsZero) PurgeModulePrefix(context.Context) error { return nil }

