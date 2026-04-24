//go:build integration

package fixture

import (
	"bytes"
	"context"
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

// --- AWS / S3 helpers ---

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

func resolveStateBucket(ctx context.Context) (string, error) {
	bucketOnce.Do(func() {
		accountID, err := ResolveAWSAccountID(ctx)
		if err != nil {
			bucketErr = err
			return
		}

		stateBucket = stateBucketPrefix + accountID
	})

	return stateBucket, bucketErr
}

// ResolveAWSAccountID returns the AWS account ID of the current caller.
func ResolveAWSAccountID(ctx context.Context) (string, error) {
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

// EnsureStateBucket verifies that the S3 state bucket exists, creating it if needed.
func EnsureStateBucket(t *testing.T) {
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

// --- Artifact management ---

func (f *BaseFixture) uploadFixtureArtifacts(ctx context.Context) error {
	client, err := newS3Client(ctx)
	if err != nil {
		return fmt.Errorf("create S3 client: %w", err)
	}

	bucket := stateBucket
	prefix := filepath.ToSlash(filepath.Dir(f.cfg.StateKey) + "/artifacts")

	err = filepath.WalkDir(f.cfg.FixtureDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if d.IsDir() && d.Name() == ".terraform" {
			return filepath.SkipDir
		}

		if d.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(f.cfg.FixtureDir, path)
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

	return err
}

func (f *BaseFixture) deleteFixtureArtifacts(ctx context.Context) error {
	client, err := newS3Client(ctx)
	if err != nil {
		return fmt.Errorf("create S3 client: %w", err)
	}

	bucket := stateBucket
	prefix := filepath.ToSlash(filepath.Dir(f.cfg.StateKey) + "/artifacts/")
	var continuationToken *string

	for {
		listOutput, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            &bucket,
			Prefix:            &prefix,
			ContinuationToken: continuationToken,
		})
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

func (f *BaseFixture) downloadArtifactsToTempDir(ctx context.Context) (string, error) {
	client, err := newS3Client(ctx)
	if err != nil {
		return "", fmt.Errorf("create S3 client: %w", err)
	}

	bucket := stateBucket
	prefix := filepath.ToSlash(filepath.Dir(f.cfg.StateKey) + "/artifacts/")

	var allKeys []string
	var continuationToken *string
	for {
		listOutput, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            &bucket,
			Prefix:            &prefix,
			ContinuationToken: continuationToken,
		})
		if err != nil {
			return "", fmt.Errorf("list artifact objects: %w", err)
		}

		for _, obj := range listOutput.Contents {
			if obj.Key != nil {
				allKeys = append(allKeys, *obj.Key)
			}
		}

		isTruncated := listOutput.IsTruncated != nil && *listOutput.IsTruncated
		if !isTruncated {
			break
		}
		continuationToken = listOutput.NextContinuationToken
	}

	if len(allKeys) == 0 {
		return "", fmt.Errorf("no remote artifacts found under %s", prefix)
	}

	tmpDir, err := os.MkdirTemp("", "aurelian-fixtures-")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}

	for _, key := range allKeys {
		relPath := strings.TrimPrefix(key, prefix)
		if relPath == "" {
			continue
		}

		destPath := filepath.Join(tmpDir, filepath.FromSlash(relPath))
		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			os.RemoveAll(tmpDir)
			return "", fmt.Errorf("create dir for %s: %w", relPath, err)
		}

		getOutput, err := client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: &bucket,
			Key:    &key,
		})
		if err != nil {
			os.RemoveAll(tmpDir)
			return "", fmt.Errorf("download artifact %s: %w", key, err)
		}

		data, err := io.ReadAll(getOutput.Body)
		getOutput.Body.Close()
		if err != nil {
			os.RemoveAll(tmpDir)
			return "", fmt.Errorf("read artifact %s: %w", key, err)
		}

		if err := os.WriteFile(destPath, data, 0o644); err != nil {
			os.RemoveAll(tmpDir)
			return "", fmt.Errorf("write artifact %s: %w", destPath, err)
		}
	}

	f.t.Logf("terraform fixture: downloaded %d artifacts to %s", len(allKeys), tmpDir)
	return tmpDir, nil
}

// --- Remote hash ---

func (f *BaseFixture) hashKey() string {
	dir := filepath.Dir(f.cfg.StateKey)
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

// purgeModulePrefix deletes every object under the module's S3 prefix
// (integration-tests/<moduleDir>/). Used after a successful teardown to
// remove the empty terraform.tfstate, the fixture.md5 hash marker, the
// artifacts/* tree, and any terraform.tfstate.tflock left by the S3
// backend.
func (f *BaseFixture) purgeModulePrefix(ctx context.Context) error {
	client, err := newS3Client(ctx)
	if err != nil {
		return fmt.Errorf("create S3 client: %w", err)
	}

	bucket := stateBucket
	prefix := filepath.ToSlash(filepath.Dir(f.cfg.StateKey)) + "/"

	var continuationToken *string
	for {
		listOutput, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            &bucket,
			Prefix:            &prefix,
			ContinuationToken: continuationToken,
		})
		if err != nil {
			return fmt.Errorf("list module prefix: %w", err)
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
				deleteOutput, err := client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
					Bucket: &bucket,
					Delete: &types.Delete{Objects: objects, Quiet: aws.Bool(true)},
				})
				if err != nil {
					return fmt.Errorf("delete module prefix objects: %w", err)
				}
				if len(deleteOutput.Errors) > 0 {
					e := deleteOutput.Errors[0]
					return fmt.Errorf("delete module prefix objects: partial failure: key=%q code=%q message=%q (and %d more)",
						aws.ToString(e.Key), aws.ToString(e.Code), aws.ToString(e.Message), len(deleteOutput.Errors)-1)
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
