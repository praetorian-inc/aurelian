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

	r := buildECRRepositoryResource(repo, newest, "123456789012", "us-east-2")

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

func TestBuildECRRepositoryResourceNoImages(t *testing.T) {
	// An empty repository is still inventory, but it has no push time. Leaving
	// LastModified nil makes a modified-since consumer fail open rather than
	// treat the repository as unchanged.
	repo := ecrtypes.Repository{
		RepositoryName: aws.String("empty"),
		RepositoryArn:  aws.String("arn:aws:ecr:eu-west-1:123456789012:repository/empty"),
		RepositoryUri:  aws.String("123456789012.dkr.ecr.eu-west-1.amazonaws.com/empty"),
	}

	r := buildECRRepositoryResource(repo, nil, "123456789012", "eu-west-1")

	assert.Equal(t, "empty", r.ResourceID)
	assert.Nil(t, r.LastModified)
	assert.Nil(t, r.Properties[ECRPropImageURI])
	assert.Nil(t, r.Properties[ECRPropImageTag])
}

func TestBuildECRRepositoryResourceUntaggedImage(t *testing.T) {
	// An image pushed by digest carries no tags. The reference falls back to
	// :latest, which is what the ECR API resolves for an untagged push.
	pushed := time.Date(2026, time.August, 20, 8, 30, 0, 0, time.UTC)
	repo := ecrtypes.Repository{
		RepositoryName: aws.String("untagged"),
		RepositoryArn:  aws.String("arn:aws:ecr:us-west-2:123456789012:repository/untagged"),
		RepositoryUri:  aws.String("123456789012.dkr.ecr.us-west-2.amazonaws.com/untagged"),
	}

	r := buildECRRepositoryResource(repo, &ecrtypes.ImageDetail{ImagePushedAt: &pushed}, "123456789012", "us-west-2")

	assert.Equal(t, "123456789012.dkr.ecr.us-west-2.amazonaws.com/untagged:latest", r.Properties[ECRPropImageURI])
	assert.Equal(t, "latest", r.Properties[ECRPropImageTag])
	assert.Equal(t, pushed, *r.LastModified)
}

func TestBuildECRRepositoryResourceNilArn(t *testing.T) {
	// A missing ARN must not panic; it falls back to a synthesized form.
	repo := ecrtypes.Repository{RepositoryName: aws.String("no-arn")}

	r := buildECRRepositoryResource(repo, nil, "123456789012", "ap-south-1")

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
