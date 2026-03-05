package enumeration

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// S3Enumerator enumerates S3 buckets using the native SDK with server-side
// region filtering, avoiding the duplicate enumeration that CloudControl causes.
type S3Enumerator struct {
	plugin.AWSCommonRecon
	provider  *AWSConfigProvider
	accountID string
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

// EnumerateByARN delegates to CloudControl for richer single-resource detail.
func (l *S3Enumerator) EnumerateByARN(_ string, _ *pipeline.P[output.AWSResource]) error {
	return errFallbackToCloudControl
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
	for {
		input := &s3.ListBucketsInput{
			BucketRegion: &region,
		}
		if continuationToken != nil {
			input.ContinuationToken = continuationToken
		}

		result, err := client.ListBuckets(context.Background(), input)
		if err != nil {
			return fmt.Errorf("list buckets in %s: %w", region, err)
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
		if continuationToken == nil {
			break
		}
	}

	return nil
}
