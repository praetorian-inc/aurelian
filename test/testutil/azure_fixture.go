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

func NewAzureFixture(t *testing.T, moduleDir string) Fixture {
	t.Helper()

	execPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Fatalf("terraform not found in PATH: %v", err)
	}

	_, thisFile, _, _ := runtime.Caller(0)
	fixtureDir := filepath.Join(filepath.Dir(thisFile), "..", "terraform", moduleDir)

	subscriptionID, err := resolveAzureSubscriptionID()
	if err != nil {
		t.Fatalf("resolve azure subscription id: %v", err)
	}

	fixture.EnsureStateBucket(t)
	stateKey := fmt.Sprintf("integration-tests/azure/%s/terraform.tfstate", moduleDir)

	return fixture.NewBase(t, fixture.Config{
		Provider:    fixture.ProviderAzure,
		ModuleDir:   moduleDir,
		FixtureDir:  fixtureDir,
		ExecPath:    execPath,
		ContainerID: subscriptionID,
		StateKey:    stateKey,
	})
}

func resolveAzureSubscriptionID() (string, error) {
	subscriptionID := os.Getenv("AZURE_SUBSCRIPTION_ID")
	if subscriptionID == "" {
		return "", errors.New("AZURE_SUBSCRIPTION_ID must be set for Azure fixture")
	}

	return subscriptionID, nil
}
