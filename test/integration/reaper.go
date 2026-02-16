//go:build integration

package integration

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/hashicorp/terraform-exec/tfexec"
	"golang.org/x/sync/errgroup"
)

// staleStack represents a Terraform stack in S3 whose timestamp exceeds the
// reaper's max age threshold.
type staleStack struct {
	// stateKey is the full S3 object key, e.g.
	// "integration-tests/aws/list/20260213T181726-abcdef01/terraform.tfstate"
	stateKey string

	// moduleDir is the terraform module relative path, e.g. "aws/list".
	moduleDir string

	// timestamp is the parsed creation time from the key path.
	timestamp time.Time
}

// Reaper finds and destroys stale integration-test Terraform stacks whose state
// files remain in S3 after a failed or interrupted test run. It is best-effort:
// all errors are logged but never fail the calling test.
type Reaper struct {
	t        *testing.T
	execPath string // absolute path to the terraform binary
	skipKey  string // S3 key to skip (the caller's own in-progress state)
	maxAge   time.Duration
}

// NewReaper creates a Reaper that will skip the given state key (to avoid
// destroying the caller's own stack) and destroy any stack older than maxAge.
func NewReaper(t *testing.T, execPath string, skipKey string, maxAge time.Duration) *Reaper {
	return &Reaper{
		t:        t,
		execPath: execPath,
		skipKey:  skipKey,
		maxAge:   maxAge,
	}
}

// Run lists all state files in the S3 bucket, identifies stacks older than
// maxAge, and destroys them concurrently.
func (r *Reaper) Run() {
	stale, err := r.listStaleStacks()
	if err != nil {
		r.t.Logf("reaper: failed to list stale stacks: %v", err)
		return
	}
	if len(stale) == 0 {
		r.t.Logf("reaper: no stale stacks found")
		return
	}

	keys := make([]string, len(stale))
	for i, s := range stale {
		keys[i] = s.stateKey
	}
	r.t.Logf("reaper: cleaning up %d stale stack(s): %s", len(stale), strings.Join(keys, ", "))

	var g errgroup.Group
	for _, stack := range stale {
		g.Go(func() error {
			r.destroyStack(stack)
			return nil
		})
	}
	_ = g.Wait()
}

// listStaleStacks enumerates all state files under statePrefix and returns those
// whose embedded timestamp is older than maxAge.
func (r *Reaper) listStaleStacks() ([]staleStack, error) {
	ctx := context.Background()
	client, err := newS3Client(ctx)
	if err != nil {
		return nil, fmt.Errorf("create S3 client: %w", err)
	}

	now := time.Now().UTC()
	var stale []staleStack

	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: strPtr(stateBucket),
		Prefix: strPtr(statePrefix),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list objects: %w", err)
		}
		for _, obj := range page.Contents {
			key := *obj.Key
			if key == r.skipKey {
				continue
			}
			stack, ok := parseStateKey(key)
			if !ok {
				continue
			}
			if now.Sub(stack.timestamp) > r.maxAge {
				stale = append(stale, stack)
			}
		}
	}
	return stale, nil
}

// destroyStack tears down a single stale Terraform stack and cleans up its
// state file from S3. It creates a temporary copy of the terraform module
// directory so it can run init+destroy without interfering with any other
// concurrent terraform working directory.
func (r *Reaper) destroyStack(stack staleStack) {
	_, thisFile, _, _ := runtime.Caller(0)
	srcDir := filepath.Join(filepath.Dir(thisFile), "terraform", stack.moduleDir)

	if _, err := os.Stat(srcDir); err != nil {
		r.t.Logf("reaper: skipping %s — module dir %q not found: %v", stack.stateKey, stack.moduleDir, err)
		return
	}

	tmpDir, err := os.MkdirTemp("", "aurelian-reaper-*")
	if err != nil {
		r.t.Logf("reaper: failed to create temp dir for %s: %v", stack.stateKey, err)
		return
	}
	defer os.RemoveAll(tmpDir)

	if err := copyDir(srcDir, tmpDir); err != nil {
		r.t.Logf("reaper: failed to copy module dir for %s: %v", stack.stateKey, err)
		return
	}

	tf, err := tfexec.NewTerraform(tmpDir, r.execPath)
	if err != nil {
		r.t.Logf("reaper: failed to create terraform instance for %s: %v", stack.stateKey, err)
		return
	}

	ctx := context.Background()

	initOpts := []tfexec.InitOption{
		tfexec.BackendConfig("bucket=" + stateBucket),
		tfexec.BackendConfig("region=" + stateRegion),
		tfexec.BackendConfig("key=" + stack.stateKey),
		tfexec.Reconfigure(true),
	}
	if err := tf.Init(ctx, initOpts...); err != nil {
		r.t.Logf("reaper: terraform init failed for %s: %v", stack.stateKey, err)
		return
	}

	r.t.Logf("reaper: destroying stale stack %s (age: %s)", stack.stateKey, time.Since(stack.timestamp).Truncate(time.Hour))

	if err := tf.Destroy(ctx); err != nil {
		r.t.Logf("reaper: terraform destroy failed for %s (state preserved): %v", stack.stateKey, err)
		return
	}

	r.deleteStateKey(stack.stateKey)
	r.t.Logf("reaper: successfully reaped %s", stack.stateKey)
}

// deleteStateKey removes a single state object from S3. Best-effort.
func (r *Reaper) deleteStateKey(key string) {
	ctx := context.Background()
	client, err := newS3Client(ctx)
	if err != nil {
		r.t.Logf("reaper: failed to create S3 client for state cleanup: %v", err)
		return
	}
	bucket := stateBucket
	_, err = client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &key,
	})
	if err != nil {
		r.t.Logf("reaper: failed to delete state s3://%s/%s: %v", stateBucket, key, err)
	}
}

// parseStateKey extracts the moduleDir and timestamp from a state key.
// Expected format: integration-tests/<moduleDir...>/<timestamp>-<runID>/terraform.tfstate
// Returns false if the key doesn't match the expected format.
func parseStateKey(key string) (staleStack, bool) {
	rest := strings.TrimPrefix(key, statePrefix)
	if rest == key {
		return staleStack{}, false
	}

	if !strings.HasSuffix(rest, "/terraform.tfstate") {
		return staleStack{}, false
	}
	rest = strings.TrimSuffix(rest, "/terraform.tfstate")

	// The last path segment is "<timestamp>-<runID>".
	// Everything before it is the moduleDir.
	lastSlash := strings.LastIndex(rest, "/")
	if lastSlash < 0 {
		return staleStack{}, false
	}
	moduleDir := rest[:lastSlash]
	timestampRunID := rest[lastSlash+1:]

	// Timestamp is "20060102T150405" (15 chars), then a dash, then hex runID.
	if len(timestampRunID) < 16 {
		return staleStack{}, false
	}
	dashIdx := strings.Index(timestampRunID, "-")
	if dashIdx < 0 {
		return staleStack{}, false
	}
	tsStr := timestampRunID[:dashIdx]

	ts, err := time.Parse("20060102T150405", tsStr)
	if err != nil {
		return staleStack{}, false
	}

	return staleStack{
		stateKey:  key,
		moduleDir: moduleDir,
		timestamp: ts,
	}, true
}

// copyDir recursively copies src to dst. Only regular files and directories are
// copied; symlinks and special files are skipped. The .terraform directory is
// excluded since the caller will run its own terraform init. dst must already exist.
func copyDir(src, dst string) error {
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.Name() == ".terraform" {
			continue
		}

		if entry.IsDir() {
			if err := os.MkdirAll(dstPath, 0o755); err != nil {
				return err
			}
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
			continue
		}

		if !entry.Type().IsRegular() {
			continue
		}

		if err := copyFile(srcPath, dstPath); err != nil {
			return fmt.Errorf("copy %s: %w", entry.Name(), err)
		}
	}
	return nil
}

// copyFile copies a single regular file from src to dst.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}
