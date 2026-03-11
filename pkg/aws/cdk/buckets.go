package cdk

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithy "github.com/aws/smithy-go"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

func validateBucket(ctx context.Context, client *s3.Client, role RoleInfo) *output.Risk {
	slog.Debug("validating bucket", "bucket", role.BucketName, "region", role.Region)
	bucketExists, ownedByAccount := checkBucketExistence(ctx, client, role.BucketName, role.AccountID)

	if !bucketExists {
		slog.Debug("bucket not found", "bucket", role.BucketName, "region", role.Region)
		return generateBucketTakeoverRisk(role)
	}
	if bucketExists && !ownedByAccount {
		slog.Debug("bucket ownership check failed", "bucket", role.BucketName, "region", role.Region)
		return generateBucketHijackedRisk(role)
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

func generateBucketTakeoverRisk(role RoleInfo) *output.Risk {
	accountArn := fmt.Sprintf("arn:aws:iam::%s:root", role.AccountID)
	return &output.Risk{
		Target: &output.AWSResource{
			ResourceType: "AWS::IAM::Root",
			ResourceID:   accountArn,
			AccountRef:   role.AccountID,
			Region:       role.Region,
			Properties: map[string]any{
				"RoleName":   role.RoleName,
				"BucketName": role.BucketName,
				"Qualifier":  role.Qualifier,
			},
		},
		Name:           "cdk-bucket-takeover",
		DNS:            role.AccountID,
		Status:         "TH",
		Source:         "aurelian-cdk-scanner",
		Description:    fmt.Sprintf("AWS CDK staging S3 bucket '%s' is missing but CDK bootstrap role '%s' exists in region %s. This allows potential account takeover through bucket name claiming and CloudFormation template injection.", role.BucketName, role.RoleName, role.Region),
		Impact:         "Attackers can claim the predictable CDK staging bucket name and inject malicious CloudFormation templates, potentially creating admin roles for account takeover.",
		Recommendation: fmt.Sprintf("Re-run 'cdk bootstrap --qualifier %s' in region %s or upgrade to CDK v2.149.0+ and re-bootstrap to apply security patches.", role.Qualifier, role.Region),
		References:     "https://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover/",
		Comment:        fmt.Sprintf("Role: %s, Expected Bucket: %s, Qualifier: %s, Region: %s", role.RoleName, role.BucketName, role.Qualifier, role.Region),
	}
}

func generateBucketHijackedRisk(role RoleInfo) *output.Risk {
	accountArn := fmt.Sprintf("arn:aws:iam::%s:root", role.AccountID)
	return &output.Risk{
		Target: &output.AWSResource{
			ResourceType: "AWS::IAM::Root",
			ResourceID:   accountArn,
			AccountRef:   role.AccountID,
			Region:       role.Region,
			Properties: map[string]any{
				"RoleName":   role.RoleName,
				"BucketName": role.BucketName,
				"Qualifier":  role.Qualifier,
			},
		},
		Name:           "cdk-bucket-hijacked",
		DNS:            role.AccountID,
		Status:         "TM",
		Source:         "aurelian-cdk-scanner",
		Description:    fmt.Sprintf("AWS CDK staging S3 bucket '%s' appears to be owned by a different account, but CDK role '%s' still exists. This indicates a potential bucket takeover.", role.BucketName, role.RoleName),
		Impact:         "CDK deployments may fail or push sensitive CloudFormation templates to an attacker-controlled bucket.",
		Recommendation: fmt.Sprintf("Verify bucket ownership and re-run 'cdk bootstrap --qualifier <new-qualifier>' with a unique qualifier in region %s.", role.Region),
		References:     "https://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover/",
		Comment:        fmt.Sprintf("Role: %s, Suspicious Bucket: %s, Qualifier: %s, Region: %s", role.RoleName, role.BucketName, role.Qualifier, role.Region),
	}
}
