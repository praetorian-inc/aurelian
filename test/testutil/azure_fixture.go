//go:build integration

package testutil

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/hashicorp/terraform-exec/tfexec"
)

const azureReaperMaxAge = 3 * 24 * time.Hour

// AzureFixture manages Terraform lifecycle for Azure integration tests.
// Unlike the AWS TerraformFixture (which uses S3 remote state), this uses
// local state stored in a stable temp directory. This avoids requiring AWS
// credentials when running Azure-only tests.
type AzureFixture struct {
	tf       *tfexec.Terraform
	outputs  map[string]tfexec.OutputMeta
	t        *testing.T
	stateDir string
}

// NewAzureFixture creates a fixture for an Azure Terraform module.
// moduleDir is relative to test/terraform/ (e.g., "azure/recon/list-all").
func NewAzureFixture(t *testing.T, moduleDir string) *AzureFixture {
	t.Helper()

	execPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Fatalf("terraform not found in PATH: %v", err)
	}

	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(thisFile), "..", "terraform", moduleDir)

	tf, err := tfexec.NewTerraform(dir, execPath)
	if err != nil {
		t.Fatalf("failed to create terraform instance for %s: %v", moduleDir, err)
	}

	// State directory for local state persistence (supports AURELIAN_KEEP_INFRA).
	// Each moduleDir gets its own subdirectory so multiple fixtures don't collide.
	stateDir := filepath.Join(os.TempDir(), "aurelian-azure-state", moduleDir)

	return &AzureFixture{tf: tf, t: t, stateDir: stateDir}
}

// Setup runs terraform init and apply, reads outputs, and registers cleanup.
// When AURELIAN_KEEP_INFRA=1 is set, cleanup is skipped so infrastructure
// persists between test runs for faster iteration.
func (f *AzureFixture) Setup() {
	f.t.Helper()
	ctx := context.Background()

	// Ensure state directory exists.
	if err := os.MkdirAll(f.stateDir, 0o755); err != nil {
		f.t.Fatalf("failed to create state directory: %v", err)
	}

	// Clean up stale state directories from previous failed runs.
	f.reapStaleState()

	// Init with local backend, pointing state at a stable temp path.
	statePath := filepath.Join(f.stateDir, "terraform.tfstate")
	f.t.Logf("terraform state: %s", statePath)

	initOpts := []tfexec.InitOption{
		tfexec.Reconfigure(true),
		tfexec.BackendConfig(fmt.Sprintf("path=%s", statePath)),
	}

	if err := f.tf.Init(ctx, initOpts...); err != nil {
		f.t.Fatalf("terraform init: %v", err)
	}

	if err := f.tf.Apply(ctx); err != nil {
		f.t.Fatalf("terraform apply: %v", err)
	}

	outputs, err := f.tf.Output(ctx)
	if err != nil {
		f.t.Fatalf("terraform output: %v", err)
	}
	f.outputs = outputs

	if os.Getenv("AURELIAN_KEEP_INFRA") == "" {
		f.t.Cleanup(func() {
			f.t.Log("terraform destroy: starting infrastructure teardown...")
			start := time.Now()
			if err := f.tf.Destroy(context.Background()); err != nil {
				f.t.Errorf("terraform destroy failed (state at %s for manual cleanup): %v", f.stateDir, err)
				return
			}
			f.t.Logf("terraform destroy: completed in %s", time.Since(start).Round(time.Second))
			os.RemoveAll(f.stateDir)
		})
	}
}

// Output returns a single string Terraform output value.
func (f *AzureFixture) Output(key string) string {
	f.t.Helper()
	meta, ok := f.outputs[key]
	if !ok {
		f.t.Fatalf("terraform output %q not found", key)
	}
	var s string
	if err := json.Unmarshal(meta.Value, &s); err != nil {
		f.t.Fatalf("terraform output %q is not a string: %s", key, string(meta.Value))
	}
	return s
}

// OutputList returns a string list Terraform output value.
func (f *AzureFixture) OutputList(key string) []string {
	f.t.Helper()
	meta, ok := f.outputs[key]
	if !ok {
		f.t.Fatalf("terraform output %q not found", key)
	}
	var result []string
	if err := json.Unmarshal(meta.Value, &result); err != nil {
		f.t.Fatalf("terraform output %q is not a string list: %s", key, string(meta.Value))
	}
	return result
}

// reapStaleState removes state directories older than azureReaperMaxAge.
// This prevents accumulation of abandoned state from previous failed runs.
func (f *AzureFixture) reapStaleState() {
	baseDir := filepath.Join(os.TempDir(), "aurelian-azure-state")
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return // no state dirs to reap
	}

	cutoff := time.Now().Add(-azureReaperMaxAge)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			path := filepath.Join(baseDir, entry.Name())
			os.RemoveAll(path)
			f.t.Logf("reaped stale Azure state directory: %s", path)
		}
	}
}
