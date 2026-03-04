//go:build integration

package testutil

import (
	"bytes"
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
	provider      fixtureProvider
	moduleDir     string
	fixtureDir    string
	execPath      string
	containerID   string
	stateKey      string
	stateURI      string
	artifactsURI  string
	initOpts      []tfexec.InitOption
}

type Fixture interface {
	Setup()
	Output(string) string
	OutputList(string) []string
}

type fixtureOps interface {
	GetRemoteHash(context.Context) (string, error)
	PutRemoteHash(context.Context, string) error
	Init(context.Context, ...tfexec.InitOption) error
	Destroy(context.Context, ...tfexec.DestroyOption) error
	Apply(context.Context, ...tfexec.ApplyOption) error
	Output(context.Context, ...tfexec.OutputOption) (map[string]tfexec.OutputMeta, error)
	UploadArtifacts(context.Context) error
	DeleteArtifacts(context.Context) error
}

type BaseFixture struct {
	tf      *tfexec.Terraform
	outputs map[string]tfexec.OutputMeta
	t       *testing.T
	cfg     fixtureConfig
	ops     fixtureOps
}

type baseFixtureOps struct {
	fixture *BaseFixture
}

func newBaseFixture(t *testing.T, cfg fixtureConfig) *BaseFixture {
	t.Helper()

	cfg = initializeStorageConfig(cfg)

	tf, err := tfexec.NewTerraform(cfg.fixtureDir, cfg.execPath)
	if err != nil {
		t.Fatalf("failed to create terraform instance for %s: %v", cfg.moduleDir, err)
	}

	fixture := &BaseFixture{tf: tf, t: t, cfg: cfg}
	fixture.ops = baseFixtureOps{fixture: fixture}

	return fixture
}

func initializeStorageConfig(cfg fixtureConfig) fixtureConfig {
	if cfg.stateURI == "" {
		cfg.stateURI = fmt.Sprintf("s3://%s/%s", stateBucket, cfg.stateKey)
	}

	if cfg.artifactsURI == "" {
		artifactsPath := filepath.ToSlash(filepath.Dir(cfg.stateKey))
		cfg.artifactsURI = fmt.Sprintf("s3://%s/%s/artifacts/", stateBucket, artifactsPath)
	}

	if len(cfg.initOpts) == 0 {
		cfg.initOpts = []tfexec.InitOption{
			tfexec.BackendConfig("bucket=" + stateBucket),
			tfexec.BackendConfig("region=" + stateRegion),
			tfexec.BackendConfig("key=" + cfg.stateKey),
			tfexec.Reconfigure(true),
		}
	}

	return cfg
}

func (o baseFixtureOps) GetRemoteHash(ctx context.Context) (string, error) {
	return o.fixture.getRemoteHash(ctx)
}

func (o baseFixtureOps) PutRemoteHash(ctx context.Context, hash string) error {
	return o.fixture.putRemoteHash(ctx, hash)
}

func (o baseFixtureOps) Init(ctx context.Context, opts ...tfexec.InitOption) error {
	return o.fixture.tf.Init(ctx, opts...)
}

func (o baseFixtureOps) Destroy(ctx context.Context, opts ...tfexec.DestroyOption) error {
	return o.fixture.tf.Destroy(ctx, opts...)
}

func (o baseFixtureOps) Apply(ctx context.Context, opts ...tfexec.ApplyOption) error {
	return o.fixture.tf.Apply(ctx, opts...)
}

func (o baseFixtureOps) Output(ctx context.Context, opts ...tfexec.OutputOption) (map[string]tfexec.OutputMeta, error) {
	return o.fixture.tf.Output(ctx, opts...)
}

func (o baseFixtureOps) UploadArtifacts(ctx context.Context) error {
	return o.fixture.uploadFixtureArtifacts(ctx)
}

func (o baseFixtureOps) DeleteArtifacts(ctx context.Context) error {
	return o.fixture.deleteFixtureArtifacts(ctx)
}

func (f *BaseFixture) Setup() {
	f.t.Helper()

	err := f.runLifecycle(context.Background())
	if err != nil {
		f.t.Fatalf("fixture setup failed: %v", err)
	}
}

func (f *BaseFixture) runLifecycle(ctx context.Context) error {
	f.t.Logf("terraform fixture state location: %s", f.cfg.stateURI)
	f.t.Logf("terraform fixture artifacts location: %s", f.cfg.artifactsURI)

	fixtureHash, err := computeFixtureHash(f.cfg.fixtureDir)
	if err != nil {
		return fmt.Errorf("compute fixture hash: %w", err)
	}
	f.t.Logf("terraform fixture local hash: %s", fixtureHash)

	effectiveHash := computeEffectiveHash(fixtureHash, f.cfg.containerID)
	remoteHash, err := f.ops.GetRemoteHash(ctx)
	if err != nil {
		return fmt.Errorf("get remote hash: %w", err)
	}

	err = f.ops.Init(ctx, f.cfg.initOpts...)
	if err != nil {
		return fmt.Errorf("terraform init: %w", err)
	}

	destroyFixtures := os.Getenv("AURELIAN_DESTROY_FIXTURES") == "1"
	if destroyFixtures {
		f.t.Log("terraform fixture hash check: AURELIAN_DESTROY_FIXTURES=1")
		f.t.Log("terraform fixture decision: teardown + redeploy (forced)")
		if err := f.redeployStack(ctx, effectiveHash); err != nil {
			return err
		}

		return f.loadOutputs(ctx)
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
	outputs, err := f.ops.Output(ctx)
	if err != nil {
		return fmt.Errorf("terraform output: %w", err)
	}

	f.outputs = outputs
	return nil
}

func (f *BaseFixture) deployStack(ctx context.Context, hash string) error {
	f.t.Log("terraform fixture action: deploy start")
	err := f.ops.Apply(ctx)
	if err != nil {
		return fmt.Errorf("terraform apply: %w", err)
	}
	f.t.Log("terraform fixture action: deploy complete")

	err = f.ops.UploadArtifacts(ctx)
	if err != nil {
		return fmt.Errorf("upload fixture artifacts: %w", err)
	}

	err = f.ops.PutRemoteHash(ctx, hash)
	if err != nil {
		return fmt.Errorf("put remote hash: %w", err)
	}

	return nil
}

func (f *BaseFixture) redeployStack(ctx context.Context, hash string) error {
	f.t.Log("terraform fixture action: teardown start")
	err := f.ops.Destroy(ctx)
	if err != nil {
		return fmt.Errorf("terraform destroy (stale): %w", err)
	}

	err = f.ops.DeleteArtifacts(ctx)
	if err != nil {
		return fmt.Errorf("delete fixture artifacts: %w", err)
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

func (f *BaseFixture) uploadFixtureArtifacts(ctx context.Context) error {
	client, err := newS3Client(ctx)
	if err != nil {
		return fmt.Errorf("create S3 client: %w", err)
	}

	bucket := stateBucket
	prefix := filepath.ToSlash(filepath.Dir(f.cfg.stateKey) + "/artifacts")

	err = filepath.WalkDir(f.cfg.fixtureDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if d.IsDir() && d.Name() == ".terraform" {
			return filepath.SkipDir
		}

		if d.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(f.cfg.fixtureDir, path)
		if err != nil {
			return fmt.Errorf("relative path for %s: %w", path, err)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read artifact %s: %w", path, err)
		}

		artifactKey := filepath.ToSlash(prefix + "/" + relPath)
		_, err = client.PutObject(ctx, &s3.PutObjectInput{
			Bucket: &bucket,
			Key:    &artifactKey,
			Body:   bytes.NewReader(data),
		})
		if err != nil {
			return fmt.Errorf("put artifact %s: %w", artifactKey, err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

func (f *BaseFixture) deleteFixtureArtifacts(ctx context.Context) error {
	client, err := newS3Client(ctx)
	if err != nil {
		return fmt.Errorf("create S3 client: %w", err)
	}

	bucket := stateBucket
	prefix := filepath.ToSlash(filepath.Dir(f.cfg.stateKey) + "/artifacts/")
	var continuationToken *string

	for {
		listInput := &s3.ListObjectsV2Input{
			Bucket:            &bucket,
			Prefix:            &prefix,
			ContinuationToken: continuationToken,
		}
		listOutput, err := client.ListObjectsV2(ctx, listInput)
		if err != nil {
			return fmt.Errorf("list artifact objects: %w", err)
		}

		if len(listOutput.Contents) > 0 {
			objects := make([]types.ObjectIdentifier, 0, len(listOutput.Contents))
			for _, object := range listOutput.Contents {
				if object.Key == nil {
					continue
				}
				objects = append(objects, types.ObjectIdentifier{Key: object.Key})
			}

			if len(objects) > 0 {
				_, err = client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
					Bucket: &bucket,
					Delete: &types.Delete{Objects: objects, Quiet: aws.Bool(true)},
				})
				if err != nil {
					return fmt.Errorf("delete artifact objects: %w", err)
				}
			}
		}

		isTruncated := listOutput.IsTruncated != nil && *listOutput.IsTruncated
		if !isTruncated {
			return nil
		}

		continuationToken = listOutput.NextContinuationToken
	}
}

func (f *BaseFixture) hashKey() string {
	dir := filepath.Dir(f.cfg.stateKey)
	return dir + "/fixture.md5"
}

func (f *BaseFixture) getRemoteHash(ctx context.Context) (string, error) {
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
