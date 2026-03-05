package enumeration

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/require"
)

func TestS3Enumerator_ResourceType(t *testing.T) {
	l := &S3Enumerator{}
	require.Equal(t, "AWS::S3::Bucket", l.ResourceType())
}

// mockS3HeadBucket implements s3HeadBucketAPI for testing.
type mockS3HeadBucket struct {
	region string
	err    error
}

func (m *mockS3HeadBucket) HeadBucket(_ context.Context, _ *s3.HeadBucketInput, _ ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &s3.HeadBucketOutput{
		BucketRegion: aws.String(m.region),
	}, nil
}

func TestS3Enumerator_EnumerateByARN(t *testing.T) {
	out := pipeline.New[output.AWSResource]()

	enumerator := &S3Enumerator{
		AWSCommonRecon: plugin.AWSCommonRecon{
			Regions: []string{"us-east-1"},
		},
		accountID:        "123456789012",
		headBucketClient: &mockS3HeadBucket{region: "us-west-2"},
	}

	go func() {
		err := enumerator.EnumerateByARN("arn:aws:s3:::my-bucket", out)
		require.NoError(t, err)
		out.Close()
	}()

	results, err := out.Collect()
	require.NoError(t, err)

	require.Len(t, results, 1)
	r := results[0]
	require.Equal(t, "AWS::S3::Bucket", r.ResourceType)
	require.Equal(t, "my-bucket", r.ResourceID)
	require.Equal(t, "arn:aws:s3:::my-bucket", r.ARN)
	require.Equal(t, "123456789012", r.AccountRef)
	require.Equal(t, "us-west-2", r.Region)
}

func TestS3Enumerator_EnumerateByARN_InvalidARN(t *testing.T) {
	enumerator := &S3Enumerator{
		AWSCommonRecon: plugin.AWSCommonRecon{
			Regions: []string{"us-east-1"},
		},
		accountID: "123456789012",
	}

	err := enumerator.EnumerateByARN("not-an-s3-arn", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid S3 ARN")
}
