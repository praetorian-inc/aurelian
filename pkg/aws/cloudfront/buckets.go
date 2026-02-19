package cloudfront

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// S3API defines the S3 operations needed for bucket existence checks.
type S3API interface {
	HeadBucket(ctx context.Context, params *s3.HeadBucketInput, optFns ...func(*s3.Options)) (*s3.HeadBucketOutput, error)
	GetBucketLocation(ctx context.Context, params *s3.GetBucketLocationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error)
}

// checkBucketExists determines whether an S3 bucket exists by calling HeadBucket.
// It returns BucketExists, BucketNotExists, or BucketUnknown based on the response.
func checkBucketExists(ctx context.Context, client S3API, bucketName string) BucketExistence {
	_, err := client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: &bucketName,
	})
	if err == nil {
		return BucketExists
	}
	return analyzeS3Error(err, bucketName)
}

// analyzeS3Error inspects an S3 error to determine whether the bucket exists.
func analyzeS3Error(err error, bucketName string) BucketExistence {
	var noSuchBucket *s3types.NoSuchBucket
	if errors.As(err, &noSuchBucket) {
		return BucketNotExists
	}

	var notFound *s3types.NotFound
	if errors.As(err, &notFound) {
		return BucketNotExists
	}

	errStr := err.Error()

	if strings.Contains(errStr, "AccessDenied") || strings.Contains(errStr, "Forbidden") || strings.Contains(errStr, "403") {
		return BucketExists
	}

	// PermanentRedirect (301) means the bucket exists in a different region.
	// Treat as existing — the bucket is not claimable.
	if strings.Contains(errStr, "PermanentRedirect") || strings.Contains(errStr, "301") {
		return BucketExists
	}

	if strings.Contains(errStr, "404") || strings.Contains(errStr, "Not Found") {
		return BucketNotExists
	}

	slog.Warn("unknown S3 error checking bucket existence", "bucket", bucketName, "error", err)
	return BucketUnknown
}

// checkDistributionOrigins checks all S3 origins for a distribution and returns
// a VulnerableDistribution for each missing bucket.
func checkDistributionOrigins(ctx context.Context, client S3API, dist DistributionInfo) []VulnerableDistribution {
	var vulnerable []VulnerableDistribution

	for _, origin := range dist.Origins {
		if origin.OriginType != "s3" {
			continue
		}

		bucketName := extractBucketName(origin.DomainName)
		if bucketName == "" {
			slog.Debug("could not extract bucket name from origin domain", "domain", origin.DomainName)
			continue
		}

		existence := checkBucketExists(ctx, client, bucketName)
		if existence == BucketNotExists {
			vulnerable = append(vulnerable, VulnerableDistribution{
				DistributionID:     dist.ID,
				DistributionDomain: dist.DomainName,
				Aliases:            dist.Aliases,
				MissingBucket:      bucketName,
				OriginDomain:       origin.DomainName,
				OriginID:           origin.ID,
				AccountID:          dist.AccountID,
			})
		}
	}

	return vulnerable
}

// findVulnerableDistributions iterates over distributions, checks each S3 origin's
// bucket, and returns VulnerableDistribution entries for any missing buckets.
func findVulnerableDistributions(ctx context.Context, client S3API, distributions []DistributionInfo) []VulnerableDistribution {
	var result []VulnerableDistribution

	for _, dist := range distributions {
		vulnerable := checkDistributionOrigins(ctx, client, dist)
		result = append(result, vulnerable...)
	}

	return result
}
