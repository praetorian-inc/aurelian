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

	"github.com/hashicorp/terraform-exec/tfexec"
)

func NewAzureFixture(t *testing.T, moduleDir string) *BaseFixture {
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

	statePath := filepath.Join(os.TempDir(), "aurelian-terraform-state", "azure", moduleDir, "terraform.tfstate")
	err = os.MkdirAll(filepath.Dir(statePath), 0o755)
	if err != nil {
		t.Fatalf("create azure state directory: %v", err)
	}

	initOpts := []tfexec.InitOption{
		tfexec.Reconfigure(true),
		tfexec.BackendConfig(fmt.Sprintf("path=%s", statePath)),
	}

	return newBaseFixture(t, fixtureConfig{
		provider:    providerAzure,
		moduleDir:   moduleDir,
		fixtureDir:  fixtureDir,
		execPath:    execPath,
		containerID: subscriptionID,
		stateKey:    statePath,
		initOpts:    initOpts,
	})
}

func resolveAzureSubscriptionID() (string, error) {
	subscriptionID := os.Getenv("AZURE_SUBSCRIPTION_ID")
	if subscriptionID == "" {
		return "", errors.New("AZURE_SUBSCRIPTION_ID must be set for Azure fixture")
	}

	return subscriptionID, nil
}
