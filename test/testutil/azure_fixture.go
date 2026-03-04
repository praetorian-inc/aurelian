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

	ensureStateBucket(t)
	stateKey := fmt.Sprintf("integration-tests/azure/%s/terraform.tfstate", moduleDir)

	return newBaseFixture(t, fixtureConfig{
		provider:    providerAzure,
		moduleDir:   moduleDir,
		fixtureDir:  fixtureDir,
		execPath:    execPath,
		containerID: subscriptionID,
		stateKey:    stateKey,
	})
}

func resolveAzureSubscriptionID() (string, error) {
	subscriptionID := os.Getenv("AZURE_SUBSCRIPTION_ID")
	if subscriptionID == "" {
		return "", errors.New("AZURE_SUBSCRIPTION_ID must be set for Azure fixture")
	}

	return subscriptionID, nil
}
