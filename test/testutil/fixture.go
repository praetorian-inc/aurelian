//go:build integration

package testutil

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/hashicorp/terraform-exec/tfexec"
)

const (
	// stateBucket is the shared S3 bucket for all integration test Terraform state.
	stateBucket = "aurelian-integration-tests"

	// stateRegion is the AWS region where the state bucket lives.
	stateRegion = "us-east-1"

	// statePrefix is the S3 key prefix under which all integration test state is stored.
	statePrefix = "integration-tests/"

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

	// fixtureDir is the absolute path to the terraform module directory on disk.
	fixtureDir string
}

// NewFixture creates a fixture for a terraform module directory.
// moduleDir is relative to test/terraform/, e.g. "aws/recon/list".
func NewFixture(t *testing.T, moduleDir string) *TerraformFixture {
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

	// Verify the state bucket is accessible with the current AWS credentials.
	verifyStateBucket(t)

	stateKey := fmt.Sprintf("integration-tests/%s/terraform.tfstate", moduleDir)

	return &TerraformFixture{
		tf:         tf,
		t:          t,
		stateKey:   stateKey,
		execPath:   execPath,
		fixtureDir: dir,
	}
}

// Setup initializes terraform and manages infrastructure lifecycle using hash-based caching.
//
// Three cases:
//  1. No remote state exists → fresh deploy (init + apply + upload hash).
//  2. Remote state exists, hashes match → reuse (init + read outputs only).
//  3. Remote state exists, hashes differ → teardown + redeploy (init + destroy + apply + upload hash).
//
// By default, infrastructure persists after the test completes.
// Set AURELIAN_DESTROY_FIXTURES=1 to destroy infrastructure when the test finishes.
func (f *TerraformFixture) Setup() {
	f.t.Helper()
	ctx := context.Background()

	localHash, err := computeFixtureHash(f.fixtureDir)
	if err != nil {
		f.t.Fatalf("compute fixture hash: %v", err)
	}
	f.t.Logf("fixture local hash: %s", localHash)

	remoteHash, err := f.getRemoteHash(ctx)
	if err != nil {
		f.t.Fatalf("get remote hash: %v", err)
	}

	initOpts := []tfexec.InitOption{
		tfexec.BackendConfig("bucket=" + stateBucket),
		tfexec.BackendConfig("region=" + stateRegion),
		tfexec.BackendConfig("key=" + f.stateKey),
		tfexec.Reconfigure(true),
	}
	if err := f.tf.Init(ctx, initOpts...); err != nil {
		f.t.Fatalf("terraform init: %v", err)
	}

	switch {
	case remoteHash == "":
		// No remote state — fresh deploy.
		f.t.Log("fixture: no cached state found, deploying fresh infrastructure")
		if err := f.tf.Apply(ctx); err != nil {
			f.t.Fatalf("terraform apply: %v", err)
		}
		if err := f.putRemoteHash(ctx, localHash); err != nil {
			f.t.Fatalf("upload fixture hash: %v", err)
		}

	case remoteHash == localHash:
		// Hashes match — reuse existing infrastructure.
		f.t.Log("fixture: cached infrastructure is up-to-date, reusing")

	default:
		// Hashes differ — destroy stale infrastructure and redeploy.
		f.t.Logf("fixture: hash mismatch (remote=%s, local=%s), tearing down and redeploying", remoteHash, localHash)
		if err := f.tf.Destroy(ctx); err != nil {
			f.t.Fatalf("terraform destroy (stale): %v", err)
		}
		if err := f.tf.Apply(ctx); err != nil {
			f.t.Fatalf("terraform apply (redeploy): %v", err)
		}
		if err := f.putRemoteHash(ctx, localHash); err != nil {
			f.t.Fatalf("upload fixture hash: %v", err)
		}
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

	if os.Getenv("AURELIAN_DESTROY_FIXTURES") == "1" {
		f.t.Cleanup(func() {
			if err := f.tf.Destroy(context.Background()); err != nil {
				f.t.Errorf("terraform destroy failed (state preserved for manual cleanup): %v", err)
				return
			}
			f.cleanupRemoteState()
			f.deleteRemoteHash(context.Background())
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

// hashKey returns the S3 key for the fixture's hash file.
func (f *TerraformFixture) hashKey() string {
	dir := filepath.Dir(f.stateKey)
	return dir + "/fixture.md5"
}

// getRemoteHash reads the fixture.md5 file from S3. Returns ("", nil) if the
// file does not exist.
func (f *TerraformFixture) getRemoteHash(ctx context.Context) (string, error) {
	client, err := newS3Client(ctx)
	if err != nil {
		return "", fmt.Errorf("create S3 client: %w", err)
	}

	key := f.hashKey()
	bucket := stateBucket
	out, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return "", nil
		}
		if strings.Contains(err.Error(), "NoSuchKey") || strings.Contains(err.Error(), "404") {
			return "", nil
		}
		return "", fmt.Errorf("get remote hash: %w", err)
	}
	defer out.Body.Close()

	data, err := io.ReadAll(out.Body)
	if err != nil {
		return "", fmt.Errorf("read remote hash body: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

// putRemoteHash uploads the fixture hash to S3.
func (f *TerraformFixture) putRemoteHash(ctx context.Context, hash string) error {
	client, err := newS3Client(ctx)
	if err != nil {
		return fmt.Errorf("create S3 client: %w", err)
	}

	key := f.hashKey()
	bucket := stateBucket
	body := strings.NewReader(hash + "\n")
	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &key,
		Body:   body,
	})
	if err != nil {
		return fmt.Errorf("put remote hash: %w", err)
	}
	return nil
}

// deleteRemoteHash removes the fixture.md5 file from S3. Best-effort.
func (f *TerraformFixture) deleteRemoteHash(ctx context.Context) {
	client, err := newS3Client(ctx)
	if err != nil {
		f.t.Logf("warning: failed to create S3 client for hash cleanup: %v", err)
		return
	}

	key := f.hashKey()
	bucket := stateBucket
	_, _ = client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
}

func strPtr(s string) *string { return &s }
