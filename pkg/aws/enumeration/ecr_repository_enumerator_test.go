package enumeration

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildECRRepositoryResource(t *testing.T) {
	pushed := time.Date(2026, time.August, 24, 12, 0, 0, 0, time.UTC)
	repo := ecrtypes.Repository{
		RepositoryName:     aws.String("app"),
		RepositoryArn:      aws.String("arn:aws:ecr:us-east-2:123456789012:repository/app"),
		RepositoryUri:      aws.String("123456789012.dkr.ecr.us-east-2.amazonaws.com/app"),
		ImageTagMutability: ecrtypes.ImageTagMutabilityMutable,
	}
	newest := &ecrtypes.ImageDetail{
		ImageTags:     []string{"v3", "latest"},
		ImagePushedAt: &pushed,
	}

	r := buildECRRepositoryResource(repo, newest, nil, "123456789012", "us-east-2")

	assert.Equal(t, "AWS::ECR::Repository", r.ResourceType)
	assert.Equal(t, "app", r.ResourceID)
	assert.Equal(t, "arn:aws:ecr:us-east-2:123456789012:repository/app", r.ARN)
	assert.Equal(t, "123456789012", r.AccountRef)
	assert.Equal(t, "us-east-2", r.Region)
	// The newest image's push time is what a modified-since consumer compares
	// against; without it the skip cannot work.
	require.NotNil(t, r.LastModified)
	assert.Equal(t, pushed, *r.LastModified)
	// The pull reference is published so a consumer does not repeat DescribeImages.
	assert.Equal(t, "123456789012.dkr.ecr.us-east-2.amazonaws.com/app:v3", r.Properties[ECRPropImageURI])
	assert.Equal(t, "v3", r.Properties[ECRPropImageTag])
	assert.Equal(t, "MUTABLE", r.Properties["ImageTagMutability"])
}

func TestBuildECRRepositoryResourcePublishesBothReferences(t *testing.T) {
	// The newest push (v3) and the "latest" tag point at different images, which
	// is exactly why both references are published: a Docker client resolves
	// "latest", while LastModified must track the newest push.
	newestPush := time.Date(2026, time.August, 24, 12, 0, 0, 0, time.UTC)
	olderPush := newestPush.Add(-48 * time.Hour)
	repo := ecrtypes.Repository{
		RepositoryName: aws.String("app"),
		RepositoryArn:  aws.String("arn:aws:ecr:us-east-2:123456789012:repository/app"),
		RepositoryUri:  aws.String("123456789012.dkr.ecr.us-east-2.amazonaws.com/app"),
	}
	newest := &ecrtypes.ImageDetail{ImageTags: []string{"v3"}, ImagePushedAt: &newestPush}
	latestTagged := &ecrtypes.ImageDetail{ImageTags: []string{"v2", "latest"}, ImagePushedAt: &olderPush}

	r := buildECRRepositoryResource(repo, newest, latestTagged, "123456789012", "us-east-2")

	assert.Equal(t, "123456789012.dkr.ecr.us-east-2.amazonaws.com/app:v3", r.Properties[ECRPropImageURI])
	assert.Equal(t, "v3", r.Properties[ECRPropImageTag])
	assert.Equal(t, "123456789012.dkr.ecr.us-east-2.amazonaws.com/app:latest", r.Properties[ECRPropLatestTagURI])
	assert.Equal(t, newestPush, *r.LastModified, "LastModified must track the newest push, not the latest tag")
	// An incremental consumer needs the latest-tagged image's OWN push time:
	// LastModified would tell it v3 changed and make it re-pull an unchanged v2.
	assert.Equal(t, olderPush.Format(time.RFC3339Nano), r.Properties[ECRPropLatestTagPushedAt])
}

func TestBuildECRRepositoryResourceNoLatestTag(t *testing.T) {
	// A version-tagged registry has no "latest" at all, so the reference is
	// absent and a consumer must decide what to do about it.
	pushed := time.Date(2026, time.August, 24, 12, 0, 0, 0, time.UTC)
	repo := ecrtypes.Repository{
		RepositoryName: aws.String("app"),
		RepositoryUri:  aws.String("123456789012.dkr.ecr.us-east-2.amazonaws.com/app"),
	}

	r := buildECRRepositoryResource(repo, &ecrtypes.ImageDetail{ImageTags: []string{"v3"}, ImagePushedAt: &pushed}, nil, "123456789012", "us-east-2")

	assert.Nil(t, r.Properties[ECRPropLatestTagURI])
	assert.Equal(t, "123456789012.dkr.ecr.us-east-2.amazonaws.com/app:v3", r.Properties[ECRPropImageURI])
}

func TestImageWithTag(t *testing.T) {
	details := []ecrtypes.ImageDetail{
		{ImageTags: []string{"v3"}},
		{ImageTags: []string{"v2", "latest"}},
		{ImageTags: []string{"v1"}},
	}

	got := imageWithTag(details, "latest")
	require.NotNil(t, got)
	assert.Equal(t, []string{"v2", "latest"}, got.ImageTags)

	assert.Nil(t, imageWithTag(details, "nope"))
	assert.Nil(t, imageWithTag(nil, "latest"))
}

func TestBuildECRRepositoryResourceNoImages(t *testing.T) {
	// An empty repository is still inventory, but it has no push time. Leaving
	// LastModified nil makes a modified-since consumer fail open rather than
	// treat the repository as unchanged.
	repo := ecrtypes.Repository{
		RepositoryName: aws.String("empty"),
		RepositoryArn:  aws.String("arn:aws:ecr:eu-west-1:123456789012:repository/empty"),
		RepositoryUri:  aws.String("123456789012.dkr.ecr.eu-west-1.amazonaws.com/empty"),
	}

	r := buildECRRepositoryResource(repo, nil, nil, "123456789012", "eu-west-1")

	assert.Equal(t, "empty", r.ResourceID)
	assert.Nil(t, r.LastModified)
	assert.Nil(t, r.Properties[ECRPropImageURI])
	assert.Nil(t, r.Properties[ECRPropImageTag])
}

func TestBuildECRRepositoryResourceUntaggedImage(t *testing.T) {
	// An image pushed by digest carries no tags, and ECR does NOT resolve it
	// under "latest". Defaulting the tag would publish a reference that either
	// fails to pull or silently resolves to a different, older image.
	pushed := time.Date(2026, time.August, 20, 8, 30, 0, 0, time.UTC)
	repo := ecrtypes.Repository{
		RepositoryName: aws.String("untagged"),
		RepositoryArn:  aws.String("arn:aws:ecr:us-west-2:123456789012:repository/untagged"),
		RepositoryUri:  aws.String("123456789012.dkr.ecr.us-west-2.amazonaws.com/untagged"),
	}
	newest := &ecrtypes.ImageDetail{
		ImagePushedAt: &pushed,
		ImageDigest:   aws.String("sha256:9f2c1e"),
	}

	r := buildECRRepositoryResource(repo, newest, nil, "123456789012", "us-west-2")

	assert.Equal(t, "123456789012.dkr.ecr.us-west-2.amazonaws.com/untagged@sha256:9f2c1e", r.Properties[ECRPropImageURI])
	assert.Equal(t, "sha256:9f2c1e", r.Properties[ECRPropImageTag])
	assert.Equal(t, pushed, *r.LastModified)
	assert.Nil(t, r.Properties[ECRPropLatestTagURI], "an untagged image is not a latest-tagged image")
}

func TestBuildECRRepositoryResourceUntaggedWithoutDigest(t *testing.T) {
	// Neither tag nor digest means nothing pullable; publish no reference rather
	// than one that cannot resolve. LastModified still records the push.
	pushed := time.Date(2026, time.August, 20, 8, 30, 0, 0, time.UTC)
	repo := ecrtypes.Repository{
		RepositoryName: aws.String("odd"),
		RepositoryUri:  aws.String("123456789012.dkr.ecr.us-west-2.amazonaws.com/odd"),
	}

	r := buildECRRepositoryResource(repo, &ecrtypes.ImageDetail{ImagePushedAt: &pushed}, nil, "123456789012", "us-west-2")

	assert.Nil(t, r.Properties[ECRPropImageURI])
	assert.Nil(t, r.Properties[ECRPropImageTag])
	assert.Equal(t, pushed, *r.LastModified)
}

func TestBuildECRRepositoryResourceNilArn(t *testing.T) {
	// A missing ARN must not panic; it falls back to a synthesized form.
	repo := ecrtypes.Repository{RepositoryName: aws.String("no-arn")}

	r := buildECRRepositoryResource(repo, nil, nil, "123456789012", "ap-south-1")

	assert.Equal(t, "arn:aws:ecr:ap-south-1:123456789012:repository/no-arn", r.ARN)
}

func TestECRRepositoryEnumeratorResourceType(t *testing.T) {
	e := NewECRRepositoryEnumerator(plugin.AWSCommonRecon{}, nil, nil)
	assert.Equal(t, "AWS::ECR::Repository", e.ResourceType())
}

func TestECRRepositoryEnumeratorEnumerateByARNRejectsBadResource(t *testing.T) {
	e := NewECRRepositoryEnumerator(plugin.AWSCommonRecon{}, nil, nil)

	for _, arn := range []string{
		"arn:aws:ecr:us-east-2:123456789012:image/app",
		"arn:aws:ecr:us-east-2:123456789012:repository/",
		"arn:aws:ecr::123456789012:repository/app",
	} {
		err := e.EnumerateByARN(arn, nil)
		require.Error(t, err, "ARN %q should be rejected before any AWS call", arn)
	}
}
