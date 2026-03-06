//go:build integration

package testutil

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/praetorian-inc/aurelian/test/testutil/fixture"
)

func NewGCPFixture(t *testing.T, moduleDir string) Fixture {
	t.Helper()

	execPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Fatalf("terraform not found in PATH: %v", err)
	}

	_, thisFile, _, _ := runtime.Caller(0)
	fixtureDir := filepath.Join(filepath.Dir(thisFile), "..", "terraform", moduleDir)

	projectID, err := resolveGCPProjectID()
	if err != nil {
		t.Fatalf("resolve gcp project id: %v", err)
	}

	// Ensure GOOGLE_PROJECT is set so the Terraform Google provider picks it up.
	if os.Getenv("GOOGLE_PROJECT") == "" {
		os.Setenv("GOOGLE_PROJECT", projectID)
	}

	fixture.EnsureStateBucket(t)
	stateKey := fmt.Sprintf("integration-tests/gcp/%s/terraform.tfstate", moduleDir)

	return fixture.NewBase(t, fixture.Config{
		Provider:    fixture.ProviderGCP,
		ModuleDir:   moduleDir,
		FixtureDir:  fixtureDir,
		ExecPath:    execPath,
		ContainerID: projectID,
		StateKey:    stateKey,
	})
}

func resolveGCPProjectID() (string, error) {
	if id := os.Getenv("GCP_PROJECT_ID"); id != "" {
		return id, nil
	}
	if id := os.Getenv("GOOGLE_PROJECT"); id != "" {
		return id, nil
	}
	return "", errors.New("GCP_PROJECT_ID or GOOGLE_PROJECT must be set for GCP fixture")
}
