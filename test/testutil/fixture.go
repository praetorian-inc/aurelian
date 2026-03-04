//go:build integration

package testutil

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/hashicorp/terraform-exec/tfexec"
)

const (
	stateBucketPrefix = "aurelian-integration-tests-"
	stateRegion       = "us-east-1"
)

var (
	stateBucket string
	bucketOnce  sync.Once
	bucketErr   error
)

type fixtureProvider string

const (
	providerAWS   fixtureProvider = "aws"
	providerAzure fixtureProvider = "azure"
)

type fixtureConfig struct {
	provider    fixtureProvider
	moduleDir   string
	fixtureDir  string
	execPath    string
	containerID string
	stateKey    string
	initOpts    []tfexec.InitOption
}

type BaseFixture struct {
	tf      *tfexec.Terraform
	outputs map[string]tfexec.OutputMeta
	t       *testing.T
	cfg     fixtureConfig

	getRemoteHashFn func(context.Context) (string, error)
	putRemoteHashFn func(context.Context, string) error
	initFn          func(context.Context, ...tfexec.InitOption) error
	destroyFn       func(context.Context, ...tfexec.DestroyOption) error
	applyFn         func(context.Context, ...tfexec.ApplyOption) error
	outputFn        func(context.Context, ...tfexec.OutputOption) (map[string]tfexec.OutputMeta, error)
}

func newBaseFixture(t *testing.T, cfg fixtureConfig) *BaseFixture {
	t.Helper()

	tf, err := tfexec.NewTerraform(cfg.fixtureDir, cfg.execPath)
	if err != nil {
		t.Fatalf("failed to create terraform instance for %s: %v", cfg.moduleDir, err)
	}

	fixture := &BaseFixture{tf: tf, t: t, cfg: cfg}
	fixture.getRemoteHashFn = fixture.getRemoteHash
	fixture.putRemoteHashFn = fixture.putRemoteHash
	fixture.initFn = fixture.tf.Init
	fixture.destroyFn = fixture.tf.Destroy
	fixture.applyFn = fixture.tf.Apply
	fixture.outputFn = fixture.tf.Output

	return fixture
}

func (f *BaseFixture) Setup() {
	f.t.Helper()

	err := f.runLifecycle(context.Background())
	if err != nil {
		f.t.Fatalf("fixture setup failed: %v", err)
	}
}

func (f *BaseFixture) runLifecycle(ctx context.Context) error {
	fixtureHash, err := computeFixtureHash(f.cfg.fixtureDir)
	if err != nil {
		return fmt.Errorf("compute fixture hash: %w", err)
	}
	f.t.Logf("terraform fixture local hash: %s", fixtureHash)

	effectiveHash := computeEffectiveHash(fixtureHash, f.cfg.containerID)
	remoteHash, err := f.getRemoteHashFn(ctx)
	if err != nil {
		return fmt.Errorf("get remote hash: %w", err)
	}

	err = f.initFn(ctx, f.cfg.initOpts...)
	if err != nil {
		return fmt.Errorf("terraform init: %w", err)
	}

	missingRemoteHash := remoteHash == ""
	if missingRemoteHash {
		f.t.Log("terraform fixture hash check: remote hash empty")
		f.t.Log("terraform fixture decision: deploy")
		if err := f.deployStack(ctx, effectiveHash); err != nil {
			return err
		}

		return f.loadOutputs(ctx)
	}

	hashMatches := remoteHash == effectiveHash
	if hashMatches {
		f.t.Log("terraform fixture hash check: hashes match")
		f.t.Log("terraform fixture decision: reuse existing fixture")
		return f.loadOutputs(ctx)
	}

	f.t.Logf("terraform fixture hash check: hashes differ (remote=%s local_effective=%s)", remoteHash, effectiveHash)
	f.t.Log("terraform fixture decision: teardown + redeploy")
	if err := f.redeployStack(ctx, effectiveHash); err != nil {
		return err
	}

	return f.loadOutputs(ctx)
}

func (f *BaseFixture) loadOutputs(ctx context.Context) error {
	outputs, err := f.outputFn(ctx)
	if err != nil {
		return fmt.Errorf("terraform output: %w", err)
	}

	f.outputs = outputs
	return nil
}

func (f *BaseFixture) deployStack(ctx context.Context, hash string) error {
	f.t.Log("terraform fixture action: deploy start")
	err := f.applyFn(ctx)
	if err != nil {
		return fmt.Errorf("terraform apply: %w", err)
	}
	f.t.Log("terraform fixture action: deploy complete")

	err = f.putRemoteHashFn(ctx, hash)
	if err != nil {
		return fmt.Errorf("put remote hash: %w", err)
	}

	return nil
}

func (f *BaseFixture) redeployStack(ctx context.Context, hash string) error {
	f.t.Log("terraform fixture action: teardown start")
	err := f.destroyFn(ctx)
	if err != nil {
		return fmt.Errorf("terraform destroy (stale): %w", err)
	}
	f.t.Log("terraform fixture action: teardown complete")

	return f.deployStack(ctx, hash)
}

func (f *BaseFixture) Output(key string) string {
	f.t.Helper()

	meta, ok := f.outputs[key]
	if !ok {
		f.t.Fatalf("terraform output %q not found", key)
	}

	var s string
	err := json.Unmarshal(meta.Value, &s)
	if err != nil {
		f.t.Fatalf("terraform output %q is not a string: %s", key, string(meta.Value))
	}

	return s
}

func (f *BaseFixture) OutputList(key string) []string {
	f.t.Helper()

	meta, ok := f.outputs[key]
	if !ok {
		f.t.Fatalf("terraform output %q not found", key)
	}

	var result []string
	err := json.Unmarshal(meta.Value, &result)
	if err != nil {
		f.t.Fatalf("terraform output %q is not a string list: %s", key, string(meta.Value))
	}

	return result
}

func computeEffectiveHash(fixtureHash, containerID string) string {
	h := md5.New()
	_, _ = fmt.Fprintf(h, "fixture=%s\ncontainer=%s\n", fixtureHash, containerID)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func resolveStateBucket(ctx context.Context) (string, error) {
	bucketOnce.Do(func() {
		accountID, err := resolveAWSAccountID(ctx)
		if err != nil {
			bucketErr = err
			return
		}

		stateBucket = stateBucketPrefix + accountID
	})

	return stateBucket, bucketErr
}

func resolveAWSAccountID(ctx context.Context) (string, error) {
	cfg, err := loadAWSConfig(ctx)
	if err != nil {
		return "", err
	}

	identity, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("STS GetCallerIdentity: %w", err)
	}

	return *identity.Account, nil
}

func ensureStateBucket(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	bucket, err := resolveStateBucket(ctx)
	if err != nil {
		t.Fatalf("failed to resolve state bucket name: %v", err)
	}

	client, err := newS3Client(ctx)
	if err != nil {
		t.Fatalf("failed to create S3 client: %v", err)
	}

	_, headErr := client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: &bucket})
	if headErr == nil {
		return
	}

	t.Logf("state bucket %q not found, creating...", bucket)
	_, createErr := client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &bucket})
	if createErr != nil {
		t.Fatalf("state bucket %q not accessible (head: %v) and creation failed: %v", bucket, headErr, createErr)
	}
}

func loadAWSConfig(ctx context.Context) (aws.Config, error) {
	opts := []func(*config.LoadOptions) error{config.WithRegion(stateRegion)}
	if profile := os.Getenv("AWS_PROFILE"); profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("load AWS config: %w", err)
	}

	return cfg, nil
}

func newS3Client(ctx context.Context) (*s3.Client, error) {
	cfg, err := loadAWSConfig(ctx)
	if err != nil {
		return nil, err
	}

	return s3.NewFromConfig(cfg), nil
}

func (f *BaseFixture) hashKey() string {
	dir := filepath.Dir(f.cfg.stateKey)
	return dir + "/fixture.md5"
}

func (f *BaseFixture) getRemoteHash(ctx context.Context) (string, error) {
	if f.cfg.provider == providerAzure {
		data, err := os.ReadFile(f.hashKey())
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		if err != nil {
			return "", fmt.Errorf("read local hash: %w", err)
		}

		return strings.TrimSpace(string(data)), nil
	}

	client, err := newS3Client(ctx)
	if err != nil {
		return "", fmt.Errorf("create S3 client: %w", err)
	}

	key := f.hashKey()
	bucket := stateBucket
	out, err := client.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &key})
	if err != nil {
		var noSuchKey *types.NoSuchKey
		if errors.As(err, &noSuchKey) {
			return "", nil
		}

		errText := err.Error()
		if strings.Contains(errText, "NoSuchKey") || strings.Contains(errText, "404") {
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

func (f *BaseFixture) putRemoteHash(ctx context.Context, hash string) error {
	if f.cfg.provider == providerAzure {
		hashPath := f.hashKey()
		err := os.WriteFile(hashPath, []byte(hash+"\n"), 0o644)
		if err != nil {
			return fmt.Errorf("write local hash: %w", err)
		}
		return nil
	}

	client, err := newS3Client(ctx)
	if err != nil {
		return fmt.Errorf("create S3 client: %w", err)
	}

	key := f.hashKey()
	bucket := stateBucket
	body := strings.NewReader(hash + "\n")
	_, err = client.PutObject(ctx, &s3.PutObjectInput{Bucket: &bucket, Key: &key, Body: body})
	if err != nil {
		return fmt.Errorf("put remote hash: %w", err)
	}

	return nil
}
