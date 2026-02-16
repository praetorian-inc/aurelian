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
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/hashicorp/terraform-exec/tfexec"
)

const (
	// stateBucket is the shared S3 bucket for all integration test Terraform state.
	stateBucket = "aurelian-integration-tests"

	// stateRegion is the AWS region where the state bucket lives.
	stateRegion = "us-east-1"

	// statePrefix is the S3 key prefix under which all integration test state is stored.
	statePrefix = "integration-tests/"

	// reaperMaxAge is the age threshold beyond which stale stacks are destroyed.
	reaperMaxAge = 5 * time.Minute //3 * 24 * time.Hour
)

// TerraformFixture manages terraform lifecycle for integration tests.
// Infrastructure is automatically created on Setup and destroyed when the test completes.
type TerraformFixture struct {
	tf      *tfexec.Terraform
	outputs map[string]tfexec.OutputMeta
	t       *testing.T

	// stateKey is the S3 object key for this test run's Terraform state.
	stateKey string

	// execPath is the absolute path to the terraform binary.
	execPath string
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

	// Verify the state bucket is accessible with the current AWS credentials.
	verifyStateBucket(t)

	runID, err := randomHex(8)
	if err != nil {
		t.Fatalf("failed to generate run ID: %v", err)
	}

	timestamp := time.Now().UTC().Format("20060102T150405")
	stateKey := fmt.Sprintf("integration-tests/%s/%s-%s/terraform.tfstate", moduleDir, timestamp, runID)

	return &TerraformFixture{tf: tf, t: t, stateKey: stateKey, execPath: execPath}
}

// Setup initializes terraform, applies infrastructure, reads outputs, and
// registers automatic cleanup. When the test finishes, infrastructure is destroyed.
// Set AURELIAN_KEEP_INFRA=1 to skip automatic destroy for faster iteration.
//
// A background reaper goroutine is launched to destroy stale stacks (older than
// 3 days) that were left behind by previous failed runs. The reaper runs
// concurrently with the main terraform apply and is awaited before Setup returns.
func (f *TerraformFixture) Setup() {
	f.t.Helper()
	ctx := context.Background()

	// Launch the reaper concurrently with our own init+apply.
	reaper := NewReaper(f.t, f.execPath, f.stateKey, reaperMaxAge)
	var reaperWg sync.WaitGroup
	reaperWg.Add(1)
	go func() {
		defer reaperWg.Done()
		reaper.Run()
	}()

	initOpts := []tfexec.InitOption{
		tfexec.BackendConfig("bucket=" + stateBucket),
		tfexec.BackendConfig("region=" + stateRegion),
		tfexec.BackendConfig("key=" + f.stateKey),
		tfexec.Reconfigure(true),
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

	if prefix, ok := f.outputs["prefix"]; ok {
		var p string
		if err := json.Unmarshal(prefix.Value, &p); err == nil {
			f.t.Logf("terraform prefix: %s", p)
		}
	}
	f.t.Logf("terraform state: s3://%s/%s", stateBucket, f.stateKey)

	// Wait for the reaper to finish before returning.
	reaperWg.Wait()

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

// verifyStateBucket checks that the S3 state bucket exists and is accessible
// with the current AWS credentials. Fails the test immediately if not.
func verifyStateBucket(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	client, err := newS3Client(ctx)
	if err != nil {
		t.Fatalf("failed to load AWS config: %v (ensure AWS_PROFILE is set correctly)", err)
	}

	_, err = client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: strPtr(stateBucket),
	})
	if err != nil {
		t.Fatalf("state bucket %q is not accessible: %v (ensure AWS_PROFILE is set and has access to the bucket)", stateBucket, err)
	}
}

// cleanupRemoteState deletes the state object from S3 after terraform destroy.
// This is best-effort; failures are logged but do not fail the test.
func (f *TerraformFixture) cleanupRemoteState() {
	ctx := context.Background()

	client, err := newS3Client(ctx)
	if err != nil {
		f.t.Logf("warning: failed to load AWS config for state cleanup: %v", err)
		return
	}

	bucket := stateBucket
	_, err = client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &f.stateKey,
	})
	if err != nil {
		f.t.Logf("warning: failed to delete remote state s3://%s/%s: %v", stateBucket, f.stateKey, err)
		return
	}

	f.t.Logf("cleaned up remote state s3://%s/%s", stateBucket, f.stateKey)
}

// newS3Client creates an S3 client configured for the state bucket region,
// respecting AWS_PROFILE if set.
func newS3Client(ctx context.Context) (*s3.Client, error) {
	opts := []func(*config.LoadOptions) error{config.WithRegion(stateRegion)}
	if profile := os.Getenv("AWS_PROFILE"); profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS config: %w", err)
	}
	return s3.NewFromConfig(cfg), nil
}

// randomHex returns a hex-encoded string of n random bytes (2n characters).
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func strPtr(s string) *string { return &s }
