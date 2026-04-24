//go:build integration

package fixture

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func lookTerraform() (string, error) {
	path, err := exec.LookPath("terraform")
	if err != nil {
		return "", fmt.Errorf("terraform binary not found: %w", err)
	}
	return path, nil
}

// locateFixtureDir returns an absolute path to test/terraform/<moduleDir>
// relative to this test file, regardless of the caller's working directory.
func locateFixtureDir(t *testing.T, moduleDir string) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	// thisFile: .../test/testutil/fixture/integration_helpers_test.go
	// target:   .../test/terraform/<moduleDir>
	root := filepath.Join(filepath.Dir(thisFile), "..", "..", "terraform", moduleDir)
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("abs path for %s: %v", root, err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("fixture dir %s: %v", abs, err)
	}
	return abs
}
