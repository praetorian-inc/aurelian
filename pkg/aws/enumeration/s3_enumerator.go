package enumeration

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// s3HeadBucketAPI is the subset of the S3 client used by EnumerateByARN.
type s3HeadBucketAPI interface {
	HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
}

// S3Enumerator enumerates S3 buckets using the native SDK with server-side
// region filtering, avoiding the duplicate enumeration that CloudControl causes.
type S3Enumerator struct {
	plugin.AWSCommonRecon
	provider         *AWSConfigProvider
	accountID        string
	headBucketClient s3HeadBucketAPI // optional; if nil, created from provider
}

// NewS3Enumerator creates an S3Enumerator that uses the native S3 SDK.
func NewS3Enumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider) *S3Enumerator {
	return &S3Enumerator{
		AWSCommonRecon: opts,
		provider:       provider,
	}
}

// ResourceType returns the CloudControl type string for S3 buckets.
func (l *S3Enumerator) ResourceType() string {
	return "AWS::S3::Bucket"
}

// EnumerateAll enumerates all S3 buckets across configured regions using
// server-side BucketRegion filtering.
func (l *S3Enumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(l.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	if err := l.resolveAccountID(); err != nil {
		return err
	}

	actor := ratelimit.NewCrossRegionActor(l.Concurrency)
	return actor.ActInRegions(l.Regions, func(region string) error {
		return l.listBucketsInRegion(region, out)
	})
}

// EnumerateByARN resolves a single S3 bucket by ARN using HeadBucket.
func (l *S3Enumerator) EnumerateByARN(arn string, out *pipeline.P[output.AWSResource]) error {
	const arnPrefix = "arn:aws:s3:::"
	hasValidPrefix := strings.HasPrefix(arn, arnPrefix)
	if !hasValidPrefix {
		return fmt.Errorf("invalid S3 ARN: %s", arn)
	}
	bucketName := strings.TrimPrefix(arn, arnPrefix)

	if len(l.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	if err := l.resolveAccountID(); err != nil {
		return err
	}

	client := l.headBucketClient
	if client == nil {
		cfg, err := l.provider.GetAWSConfig(l.Regions[0])
		if err != nil {
			return fmt.Errorf("create S3 client: %w", err)
		}
		client = s3.NewFromConfig(*cfg)
	}

	result, err := client.HeadBucket(context.Background(), &s3.HeadBucketInput{
		Bucket: &bucketName,
	})
	if err != nil {
		return fmt.Errorf("head bucket %s: %w", bucketName, err)
	}

	region := aws.ToString(result.BucketRegion)
	out.Send(output.AWSResource{
		ResourceType: "AWS::S3::Bucket",
		ResourceID:   bucketName,
		ARN:          arn,
		AccountRef:   l.accountID,
		Region:       region,
	})

	return nil
}

func (l *S3Enumerator) resolveAccountID() error {
	if l.accountID != "" {
		return nil
	}
	if l.provider == nil {
		return fmt.Errorf("no provider configured")
	}

	id, err := l.provider.GetAccountID(l.Regions[0])
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}
	l.accountID = id
	return nil
}

func (l *S3Enumerator) listBucketsInRegion(region string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := l.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create S3 client for %s: %w", region, err)
	}
	client := s3.NewFromConfig(*cfg)

	var continuationToken *string
	paginator := ratelimit.NewPaginator()
	return paginator.Paginate(func() (bool, error) {
		input := &s3.ListBucketsInput{
			BucketRegion: &region,
		}
		if continuationToken != nil {
			input.ContinuationToken = continuationToken
		}

		result, err := client.ListBuckets(context.Background(), input)
		if err != nil {
			return false, fmt.Errorf("list buckets in %s: %w", region, err)
		}

		for _, bucket := range result.Buckets {
			name := aws.ToString(bucket.Name)
			out.Send(output.AWSResource{
				ResourceType: "AWS::S3::Bucket",
				ResourceID:   name,
				ARN:          fmt.Sprintf("arn:aws:s3:::%s", name),
				AccountRef:   l.accountID,
				Region:       region,
			})
		}

		continuationToken = result.ContinuationToken
		hasMorePages := continuationToken != nil
		return hasMorePages, nil
	})
}
