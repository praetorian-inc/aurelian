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

// checkBucketExists determines whether an S3 bucket exists and is owned by the
// current account. On a PermanentRedirect (bucket exists globally but in a
// different region), it falls through to GetBucketLocation to verify ownership.
func checkBucketExists(ctx context.Context, client S3API, bucketName string) BucketExistence {
	_, err := client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: &bucketName,
	})
	if err == nil {
		return BucketExists
	}

	existence, needsOwnershipCheck := analyzeS3Error(err, bucketName)
	if !needsOwnershipCheck {
		return existence
	}

	// PermanentRedirect means the bucket exists globally but may not be in our
	// account. Verify ownership via GetBucketLocation.
	return verifyBucketOwnership(ctx, client, bucketName)
}

// analyzeS3Error inspects an S3 error to determine whether the bucket exists.
// The second return value indicates whether an ownership check is needed (true
// on PermanentRedirect, where the bucket exists globally but the owner is unknown).
func analyzeS3Error(err error, bucketName string) (BucketExistence, bool) {
	var noSuchBucket *s3types.NoSuchBucket
	if errors.As(err, &noSuchBucket) {
		return BucketNotExists, false
	}

	var notFound *s3types.NotFound
	if errors.As(err, &notFound) {
		return BucketNotExists, false
	}

	errStr := err.Error()

	if strings.Contains(errStr, "AccessDenied") || strings.Contains(errStr, "Forbidden") || strings.Contains(errStr, "403") {
		return BucketExists, false
	}

	// PermanentRedirect (301) means the bucket exists in a different region.
	// We cannot determine ownership from HeadBucket alone — the bucket could
	// belong to another account (possibly already claimed by an attacker).
	if strings.Contains(errStr, "PermanentRedirect") || strings.Contains(errStr, "301") {
		return BucketUnknown, true
	}

	if strings.Contains(errStr, "404") || strings.Contains(errStr, "Not Found") {
		return BucketNotExists, false
	}

	slog.Warn("unknown S3 error checking bucket existence", "bucket", bucketName, "error", err)
	return BucketUnknown, false
}

// verifyBucketOwnership uses GetBucketLocation to confirm whether a bucket is
// accessible to the current account's credentials. This is called after a
// PermanentRedirect from HeadBucket, which proves global existence but not
// account ownership — a critical distinction for takeover detection.
func verifyBucketOwnership(ctx context.Context, client S3API, bucketName string) BucketExistence {
	_, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
		Bucket: &bucketName,
	})
	if err == nil {
		slog.Debug("bucket ownership verified via GetBucketLocation", "bucket", bucketName)
		return BucketExists
	}

	errStr := err.Error()
	if strings.Contains(errStr, "AccessDenied") || strings.Contains(errStr, "Forbidden") || strings.Contains(errStr, "403") {
		slog.Warn("bucket exists but is not owned by current account", "bucket", bucketName)
		return BucketExistsNotOwned
	}

	var noSuchBucket *s3types.NoSuchBucket
	if errors.As(err, &noSuchBucket) {
		return BucketNotExists
	}

	var notFound *s3types.NotFound
	if errors.As(err, &notFound) {
		return BucketNotExists
	}

	slog.Warn("could not verify bucket ownership", "bucket", bucketName, "error", err)
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
		if existence == BucketNotExists || existence == BucketExistsNotOwned {
			vulnerable = append(vulnerable, VulnerableDistribution{
				DistributionID:     dist.ID,
				DistributionDomain: dist.DomainName,
				Aliases:            dist.Aliases,
				MissingBucket:      bucketName,
				OriginDomain:       origin.DomainName,
				OriginID:           origin.ID,
				AccountID:          dist.AccountID,
				BucketState:        existence,
			})
		}
	}

	return vulnerable
}
