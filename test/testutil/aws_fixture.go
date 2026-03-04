//go:build integration

package testutil

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func NewAWSFixture(t *testing.T, moduleDir string) Fixture {
	t.Helper()

	execPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Fatalf("terraform not found in PATH: %v", err)
	}

	_, thisFile, _, _ := runtime.Caller(0)
	fixtureDir := filepath.Join(filepath.Dir(thisFile), "..", "terraform", moduleDir)

	ensureStateBucket(t)
	containerID, err := resolveAWSAccountID(context.Background())
	if err != nil {
		t.Fatalf("resolve aws account id: %v", err)
	}

	stateKey := fmt.Sprintf("integration-tests/%s/terraform.tfstate", moduleDir)

	return newBaseFixture(t, fixtureConfig{
		provider:    providerAWS,
		moduleDir:   moduleDir,
		fixtureDir:  fixtureDir,
		execPath:    execPath,
		containerID: containerID,
		stateKey:    stateKey,
	})
}
