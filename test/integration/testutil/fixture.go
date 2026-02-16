//go:build integration

package testutil

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-exec/tfexec"
)

// TerraformFixture manages terraform lifecycle for integration tests.
// Infrastructure is automatically created on Setup and destroyed when the test completes.
type TerraformFixture struct {
	tf      *tfexec.Terraform
	outputs map[string]tfexec.OutputMeta
	t       *testing.T
}

// NewFixture creates a fixture for a terraform module directory.
// moduleDir is relative to terraform/, e.g. "aws/find-secrets".
func NewFixture(t *testing.T, moduleDir string) *TerraformFixture {
	t.Helper()

	execPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Fatalf("terraform not found in PATH: %v", err)
	}

	dir := filepath.Join("terraform", moduleDir)
	tf, err := tfexec.NewTerraform(dir, execPath)
	if err != nil {
		t.Fatalf("failed to create terraform instance for %s: %v", moduleDir, err)
	}

	return &TerraformFixture{tf: tf, t: t}
}

// Setup initializes terraform, applies infrastructure, reads outputs, and
// registers automatic cleanup. When the test finishes, infrastructure is destroyed.
// Set AURELIAN_KEEP_INFRA=1 to skip automatic destroy for faster iteration.
func (f *TerraformFixture) Setup() {
	f.t.Helper()
	ctx := context.Background()

	if err := f.tf.Init(ctx); err != nil {
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
			if err := f.tf.Destroy(context.Background()); err != nil {
				f.t.Errorf("terraform destroy failed: %v", err)
			}
		})
	}
}

// Output returns a string output value by key.
func (f *TerraformFixture) Output(key string) string {
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

// OutputList returns a []string output value by key.
func (f *TerraformFixture) OutputList(key string) []string {
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
