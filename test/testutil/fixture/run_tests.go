//go:build integration

package fixture

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// destroyTimeout bounds a single DestroyAll pass. Sized generously to
// accommodate slow cloud teardowns (EKS, CloudFront) without running up
// against typical `go test -timeout 30m` ceilings. This is an outer
// bound — DestroyAll additionally enforces a per-fixture timeout.
const destroyTimeout = 15 * time.Minute

// runner is the interface satisfied by *testing.M; declared here so
// runTestsWith can be unit-tested with a stub.
type runner interface {
	Run() int
}

// RunTests wraps testing.M.Run, then — if tests passed and the user
// didn't opt out via AURELIAN_KEEP_FIXTURES — destroys every fixture
// that was Setup()'d during this test binary's execution.
//
// Intended usage, one per integration-test package:
//
//	func TestMain(m *testing.M) { os.Exit(fixture.RunTests(m)) }
func RunTests(m *testing.M) int {
	return runTestsWith(m, globalDestroyAll, os.Getenv)
}

func runTestsWith(m runner, destroyFn func(context.Context) error, getenv func(string) string) int {
	code := m.Run()
	if code != 0 {
		return code
	}

	if getenv("AURELIAN_KEEP_FIXTURES") == "1" {
		return code
	}

	ctx, cancel := context.WithTimeout(context.Background(), destroyTimeout)
	defer cancel()

	if err := destroyFn(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "[fixture] cleanup failures: %v\n", err)
		return 1
	}
	return code
}

func globalDestroyAll(ctx context.Context) error {
	return globalRegistry.DestroyAll(ctx)
}
