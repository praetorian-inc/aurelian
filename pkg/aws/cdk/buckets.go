package cdk

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithy "github.com/aws/smithy-go"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
)

func validateBucket(ctx context.Context, client *s3.Client, role RoleInfo) *capmodel.Risk {
	slog.Debug("validating bucket", "bucket", role.BucketName, "region", role.Region)
	bucketExists, ownedByAccount := checkBucketExistence(ctx, client, role.BucketName, role.AccountID)

	if !bucketExists {
		slog.Debug("bucket not found", "bucket", role.BucketName, "region", role.Region)
		risk, err := NewBucketTakeoverRisk(role)
		if err != nil {
			slog.Warn("build cdk bucket-takeover risk", "role", role.RoleName, "error", err)
			return nil
		}
		return &risk
	}
	if bucketExists && !ownedByAccount {
		slog.Debug("bucket ownership check failed", "bucket", role.BucketName, "region", role.Region)
		risk, err := NewBucketHijackedRisk(role)
		if err != nil {
			slog.Warn("build cdk bucket-hijacked risk", "role", role.RoleName, "error", err)
			return nil
		}
		return &risk
	}
	slog.Debug("bucket owned by account", "bucket", role.BucketName, "region", role.Region)
	return nil
}

func checkBucketExistence(ctx context.Context, client *s3.Client, bucketName, expectedAccountID string) (exists bool, ownedByAccount bool) {
	_, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
		Bucket: &bucketName,
	})
	if err != nil {
		var noSuchBucket *s3types.NoSuchBucket
		if errors.As(err, &noSuchBucket) {
			return false, false
		}
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && (apiErr.ErrorCode() == "AccessDenied" || apiErr.ErrorCode() == "AccessDeniedException" || apiErr.ErrorCode() == "403") {
			slog.Debug("access denied checking bucket location", "bucket", bucketName)
			return true, false
		}
		return false, false
	}

	owned := verifyBucketOwnership(ctx, client, bucketName, expectedAccountID)
	return true, owned
}

func verifyBucketOwnership(ctx context.Context, client *s3.Client, bucketName, expectedAccountID string) bool {
	result, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: &bucketName,
	})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "NoSuchBucketPolicy" {
			return true
		}
		return false
	}
	// If we can read the bucket policy, verify our account ID appears in it.
	// A policy referencing a different account is suspicious.
	if result.Policy != nil {
		return strings.Contains(*result.Policy, expectedAccountID)
	}
	return false
}
