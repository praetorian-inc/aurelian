//go:build integration

package testutil

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/praetorian-inc/aurelian/test/testutil/fixture"
)

func NewAWSFixture(t *testing.T, moduleDir string) Fixture {
	t.Helper()

	execPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Fatalf("terraform not found in PATH: %v", err)
	}

	_, thisFile, _, _ := runtime.Caller(0)
	fixtureDir := filepath.Join(filepath.Dir(thisFile), "..", "terraform", moduleDir)

	fixture.EnsureStateBucket(t)
	containerID, err := fixture.ResolveAWSAccountID(context.Background())
	if err != nil {
		t.Fatalf("resolve aws account id: %v", err)
	}

	stateKey := fmt.Sprintf("integration-tests/%s/terraform.tfstate", moduleDir)

	return fixture.NewBase(t, fixture.Config{
		Provider:    fixture.ProviderAWS,
		ModuleDir:   moduleDir,
		FixtureDir:  fixtureDir,
		ExecPath:    execPath,
		ContainerID: containerID,
		StateKey:    stateKey,
	})
}
