package enumeration

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/require"
)

type mockListBucketsClient struct {
	calls   []s3.ListBucketsInput
	outputs []*s3.ListBucketsOutput
	callIdx int
}

func (m *mockListBucketsClient) ListBuckets(_ context.Context, input *s3.ListBucketsInput, _ ...func(*s3.Options)) (*s3.ListBucketsOutput, error) {
	m.calls = append(m.calls, *input)
	out := m.outputs[m.callIdx]
	m.callIdx++
	return out, nil
}

func TestS3Enumerator_ResourceType(t *testing.T) {
	l := &S3Enumerator{}
	require.Equal(t, "AWS::S3::Bucket", l.ResourceType())
}

func TestS3Enumerator_EnumerateAll_SingleRegion_NoPagination(t *testing.T) {
	mock := &mockListBucketsClient{
		outputs: []*s3.ListBucketsOutput{
			{
				Buckets: []s3types.Bucket{
					{Name: aws.String("my-bucket")},
					{Name: aws.String("other-bucket")},
				},
			},
		},
	}

	lister := &S3Enumerator{
		AWSCommonRecon: plugin.AWSCommonRecon{
			Regions:     []string{"us-east-1"},
			Concurrency: 1,
		},
		accountID:     "123456789012",
		clientFactory: func(region string) (ListBucketsAPI, error) { return mock, nil },
	}

	out := pipeline.New[output.AWSResource]()
	var results []output.AWSResource
	done := make(chan struct{})
	go func() {
		for r := range out.Range() {
			results = append(results, r)
		}
		close(done)
	}()

	err := lister.EnumerateAll(out)
	out.Close()
	<-done

	require.NoError(t, err)
	require.Len(t, results, 2)
	require.Equal(t, "my-bucket", results[0].ResourceID)
	require.Equal(t, "AWS::S3::Bucket", results[0].ResourceType)
	require.Equal(t, "arn:aws:s3:::my-bucket", results[0].ARN)

	require.Len(t, mock.calls, 1)
	require.NotNil(t, mock.calls[0].BucketRegion)
	require.Equal(t, "us-east-1", *mock.calls[0].BucketRegion)
}

func TestS3Enumerator_EnumerateAll_Pagination(t *testing.T) {
	token := "page2"
	mock := &mockListBucketsClient{
		outputs: []*s3.ListBucketsOutput{
			{
				Buckets:           []s3types.Bucket{{Name: aws.String("bucket-1")}},
				ContinuationToken: &token,
			},
			{
				Buckets: []s3types.Bucket{{Name: aws.String("bucket-2")}},
			},
		},
	}

	lister := &S3Enumerator{
		AWSCommonRecon: plugin.AWSCommonRecon{
			Regions:     []string{"us-west-2"},
			Concurrency: 1,
		},
		accountID:     "123456789012",
		clientFactory: func(region string) (ListBucketsAPI, error) { return mock, nil },
	}

	out := pipeline.New[output.AWSResource]()
	var results []output.AWSResource
	done := make(chan struct{})
	go func() {
		for r := range out.Range() {
			results = append(results, r)
		}
		close(done)
	}()

	err := lister.EnumerateAll(out)
	out.Close()
	<-done

	require.NoError(t, err)
	require.Len(t, results, 2)
	require.Equal(t, "bucket-1", results[0].ResourceID)
	require.Equal(t, "bucket-2", results[1].ResourceID)

	require.Len(t, mock.calls, 2)
	require.NotNil(t, mock.calls[1].ContinuationToken)
	require.Equal(t, token, *mock.calls[1].ContinuationToken)
}

func TestS3Enumerator_EnumerateAll_MultiRegion(t *testing.T) {
	callCount := 0
	mock := &mockListBucketsClient{
		outputs: []*s3.ListBucketsOutput{
			{Buckets: []s3types.Bucket{{Name: aws.String("east-bucket")}}},
			{Buckets: []s3types.Bucket{{Name: aws.String("west-bucket")}}},
		},
	}

	lister := &S3Enumerator{
		AWSCommonRecon: plugin.AWSCommonRecon{
			Regions:     []string{"us-east-1", "us-west-2"},
			Concurrency: 1,
		},
		accountID: "123456789012",
		clientFactory: func(region string) (ListBucketsAPI, error) {
			callCount++
			return mock, nil
		},
	}

	out := pipeline.New[output.AWSResource]()
	var results []output.AWSResource
	done := make(chan struct{})
	go func() {
		for r := range out.Range() {
			results = append(results, r)
		}
		close(done)
	}()

	err := lister.EnumerateAll(out)
	out.Close()
	<-done

	require.NoError(t, err)
	require.Len(t, results, 2)
	require.Len(t, mock.calls, 2)
}

func TestS3Enumerator_EnumerateByARN_ReturnsFallback(t *testing.T) {
	lister := &S3Enumerator{}
	err := lister.EnumerateByARN("arn:aws:s3:::my-bucket", nil)
	require.ErrorIs(t, err, errFallbackToCloudControl)
}
