//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/hashicorp/terraform-exec/tfexec"
)

// TerraformFixture manages terraform lifecycle for integration tests.
// Infrastructure is automatically created on Setup and destroyed when the test completes.
type TerraformFixture struct {
	tf      *tfexec.Terraform
	outputs map[string]tfexec.OutputMeta
	t       *testing.T

	// Remote state fields (populated when AURELIAN_TF_STATE_BUCKET is set)
	stateBucket string
	stateRegion string
	stateKey    string
}

// NewFixture creates a fixture for a terraform module directory.
// moduleDir is relative to terraform/, e.g. "aws/find-secrets".
func NewFixture(t *testing.T, moduleDir string) *TerraformFixture {
	t.Helper()

	execPath, err := exec.LookPath("terraform")
	if err != nil {
		t.Fatalf("terraform not found in PATH: %v", err)
	}

	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Join(filepath.Dir(thisFile), "terraform", moduleDir)
	tf, err := tfexec.NewTerraform(dir, execPath)
	if err != nil {
		t.Fatalf("failed to create terraform instance for %s: %v", moduleDir, err)
	}

	f := &TerraformFixture{tf: tf, t: t}

	// Configure remote state if the shared bucket is set.
	if bucket := os.Getenv("AURELIAN_TF_STATE_BUCKET"); bucket != "" {
		region := os.Getenv("AURELIAN_TF_STATE_REGION")
		if region == "" {
			t.Fatalf("AURELIAN_TF_STATE_REGION must be set when AURELIAN_TF_STATE_BUCKET is set")
		}

		runID, err := randomHex(8)
		if err != nil {
			t.Fatalf("failed to generate run ID: %v", err)
		}

		timestamp := time.Now().UTC().Format("20060102T150405")
		stateKey := fmt.Sprintf("integration-tests/%s/%s-%s/terraform.tfstate", moduleDir, timestamp, runID)

		f.stateBucket = bucket
		f.stateRegion = region
		f.stateKey = stateKey
	}

	return f
}

// Setup initializes terraform, applies infrastructure, reads outputs, and
// registers automatic cleanup. When the test finishes, infrastructure is destroyed.
// Set AURELIAN_KEEP_INFRA=1 to skip automatic destroy for faster iteration.
func (f *TerraformFixture) Setup() {
	f.t.Helper()
	ctx := context.Background()

	initOpts := f.buildInitOptions()
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

	if prefix, ok := f.outputs["prefix"]; ok {
		var p string
		if err := json.Unmarshal(prefix.Value, &p); err == nil {
			f.t.Logf("terraform prefix: %s", p)
		}
	}
	if f.stateKey != "" {
		f.t.Logf("terraform state: s3://%s/%s", f.stateBucket, f.stateKey)
	}

	if os.Getenv("AURELIAN_KEEP_INFRA") == "" {
		f.t.Cleanup(func() {
			if err := f.tf.Destroy(context.Background()); err != nil {
				f.t.Errorf("terraform destroy failed (state preserved for manual cleanup): %v", err)
				return
			}
			f.cleanupRemoteState()
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

// buildInitOptions returns the tfexec.InitOption slice for terraform init.
// When remote state is configured, it passes -backend-config and -reconfigure flags.
func (f *TerraformFixture) buildInitOptions() []tfexec.InitOption {
	if f.stateBucket == "" {
		return nil
	}

	return []tfexec.InitOption{
		tfexec.BackendConfig("bucket=" + f.stateBucket),
		tfexec.BackendConfig("region=" + f.stateRegion),
		tfexec.BackendConfig("key=" + f.stateKey),
		tfexec.Reconfigure(true),
	}
}

// cleanupRemoteState deletes the state object from S3 after terraform destroy.
// This is best-effort; failures are logged but do not fail the test.
func (f *TerraformFixture) cleanupRemoteState() {
	if f.stateBucket == "" {
		return
	}

	ctx := context.Background()

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(f.stateRegion))
	if err != nil {
		f.t.Logf("warning: failed to load AWS config for state cleanup: %v", err)
		return
	}

	client := s3.NewFromConfig(cfg)
	_, err = client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &f.stateBucket,
		Key:    &f.stateKey,
	})
	if err != nil {
		f.t.Logf("warning: failed to delete remote state s3://%s/%s: %v", f.stateBucket, f.stateKey, err)
		return
	}

	f.t.Logf("cleaned up remote state s3://%s/%s", f.stateBucket, f.stateKey)
}

// randomHex returns a hex-encoded string of n random bytes (2n characters).
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
