package resourcepolicies

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithy "github.com/aws/smithy-go"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// S3ExtendedClient extends the S3Client interface with ACL and Block Public Access operations.
type S3ExtendedClient interface {
	S3Client
	GetBucketAcl(ctx context.Context, params *s3.GetBucketAclInput, optFns ...func(*s3.Options)) (*s3.GetBucketAclOutput, error)
	GetPublicAccessBlock(ctx context.Context, params *s3.GetPublicAccessBlockInput, optFns ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error)
	GetBucketLocation(ctx context.Context, params *s3.GetBucketLocationInput, optFns ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error)
}

// FetchS3BucketPolicyExtended retrieves the complete public access configuration for an S3 bucket:
// 1. Block Public Access settings (if restricting, return a virtual deny policy)
// 2. Bucket policy
// 3. Bucket ACL (converted to policy statements if public grants exist)
func FetchS3BucketPolicyExtended(ctx context.Context, client S3ExtendedClient, resource *output.CloudResource, allowedRegions []string) (*types.Policy, error) {
	bucketName, ok := resource.Properties["BucketName"].(string)
	if !ok || bucketName == "" {
		return nil, nil
	}

	// Always resolve the bucket's region so subsequent API calls use the correct endpoint
	locOut, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
		Bucket: &bucketName,
	})
	if err != nil {
		return nil, handleS3Error(err, "get bucket location")
	}

	bucketRegion := string(locOut.LocationConstraint)
	if bucketRegion == "" {
		bucketRegion = "us-east-1" // Default region if not set
	}

	// Filter by allowed regions if specified
	if len(allowedRegions) > 0 && !contains(allowedRegions, bucketRegion) {
		return nil, nil // Skip bucket outside allowed regions
	}

	withRegion := func(o *s3.Options) {
		o.Region = bucketRegion
	}

	// Check Block Public Access
	blockOut, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: &bucketName,
	}, withRegion)
	if err != nil {
		// NoSuchPublicAccessBlockConfiguration means no block is configured
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "NoSuchPublicAccessBlockConfiguration" {
			return nil, handleS3Error(err, "get public access block")
		}
		// No block configured - proceed to check policy and ACL
	} else if blockOut.PublicAccessBlockConfiguration != nil {
		config := blockOut.PublicAccessBlockConfiguration
		if boolPtrVal(config.IgnorePublicAcls) || boolPtrVal(config.RestrictPublicBuckets) {
			resource.Properties["BlockPublicAccess"] = map[string]bool{
				"BlockPublicAcls":       boolPtrVal(config.BlockPublicAcls),
				"IgnorePublicAcls":      boolPtrVal(config.IgnorePublicAcls),
				"BlockPublicPolicy":     boolPtrVal(config.BlockPublicPolicy),
				"RestrictPublicBuckets": boolPtrVal(config.RestrictPublicBuckets),
			}
			// If RestrictPublicBuckets is set, public policies are restricted
			// If IgnorePublicAcls is set, public ACLs are ignored
			// Return a virtual deny policy
			return createBlockPublicAccessDenyPolicy(bucketName), nil
		}
	}

	// Get bucket policy
	bucketPolicy, err := FetchS3BucketPolicy(ctx, client, resource, withRegion)
	if err != nil {
		return nil, err
	}

	// Get bucket ACL and convert public grants to policy statements
	aclStatements, err := fetchAndConvertACL(ctx, client, bucketName, withRegion)
	if err != nil {
		return nil, err
	}

	// Merge bucket policy with ACL-derived statements
	return mergeS3Policies(bucketPolicy, aclStatements, bucketName), nil
}

// fetchAndConvertACL fetches the bucket ACL and converts public grants to policy statements.
func fetchAndConvertACL(ctx context.Context, client S3ExtendedClient, bucketName string, optFns ...func(*s3.Options)) ([]types.PolicyStatement, error) {
	aclOut, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
		Bucket: &bucketName,
	}, optFns...)
	if err != nil {
		return nil, handleS3Error(err, "get bucket ACL")
	}

	return ConvertACLGrantsToStatements(aclOut.Grants, bucketName), nil
}

// ConvertACLGrantsToStatements converts S3 ACL grants that reference AllUsers or AuthenticatedUsers
// into equivalent IAM policy statements.
func ConvertACLGrantsToStatements(grants []s3types.Grant, bucketName string) []types.PolicyStatement {
	var statements []types.PolicyStatement

	for _, grant := range grants {
		if grant.Grantee == nil {
			continue
		}

		var principalArn string
		switch {
		case grant.Grantee.URI != nil && *grant.Grantee.URI == "http://acs.amazonaws.com/groups/global/AllUsers":
			principalArn = "*"
		case grant.Grantee.URI != nil && *grant.Grantee.URI == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers":
			principalArn = "*" // AuthenticatedUsers is effectively public from a security perspective
		default:
			continue // Skip non-public grants
		}

		actions := aclPermissionToActions(grant.Permission)
		if len(actions) == 0 {
			continue
		}

		stmt := types.PolicyStatement{
			Sid:    fmt.Sprintf("ACL-%s", string(grant.Permission)),
			Effect: "Allow",
			Principal: &types.Principal{
				AWS: types.NewDynaString([]string{principalArn}),
			},
			Action:   types.NewDynaString(actions),
			Resource: types.NewDynaString([]string{fmt.Sprintf("arn:aws:s3:::%s", bucketName), fmt.Sprintf("arn:aws:s3:::%s/*", bucketName)}),
		}
		statements = append(statements, stmt)
	}

	return statements
}

// aclPermissionToActions converts an S3 ACL permission to equivalent IAM actions.
func aclPermissionToActions(permission s3types.Permission) []string {
	switch permission {
	case s3types.PermissionRead:
		return []string{"s3:GetObject", "s3:ListBucket"}
	case s3types.PermissionWrite:
		return []string{"s3:PutObject", "s3:DeleteObject"}
	case s3types.PermissionReadAcp:
		return []string{"s3:GetBucketAcl", "s3:GetObjectAcl"}
	case s3types.PermissionWriteAcp:
		return []string{"s3:PutBucketAcl", "s3:PutObjectAcl"}
	case s3types.PermissionFullControl:
		return []string{"s3:*"}
	default:
		return nil
	}
}

// createBlockPublicAccessDenyPolicy creates a virtual deny policy representing
// Block Public Access settings that prevent public access.
func createBlockPublicAccessDenyPolicy(bucketName string) *types.Policy {
	stmts := types.PolicyStatementList{
		{
			Sid:    "BlockPublicAccess",
			Effect: "Deny",
			Principal: &types.Principal{
				AWS: types.NewDynaString([]string{"*"}),
			},
			Action:   types.NewDynaString([]string{"s3:*"}),
			Resource: types.NewDynaString([]string{fmt.Sprintf("arn:aws:s3:::%s", bucketName), fmt.Sprintf("arn:aws:s3:::%s/*", bucketName)}),
		},
	}
	return &types.Policy{
		Version:   "2012-10-17",
		Statement: &stmts,
	}
}

// mergeS3Policies merges a bucket policy with ACL-derived statements.
func mergeS3Policies(bucketPolicy *types.Policy, aclStatements []types.PolicyStatement, bucketName string) *types.Policy {
	if bucketPolicy == nil && len(aclStatements) == 0 {
		return nil
	}

	if bucketPolicy == nil && len(aclStatements) > 0 {
		stmts := types.PolicyStatementList(aclStatements)
		return &types.Policy{
			Version:   "2012-10-17",
			Statement: &stmts,
		}
	}

	if len(aclStatements) > 0 && bucketPolicy.Statement != nil {
		merged := append(*bucketPolicy.Statement, aclStatements...)
		bucketPolicy.Statement = &merged
	}

	return bucketPolicy
}

func handleS3Error(err error, operation string) error {
	var noSuchBucket *s3types.NoSuchBucket
	if errors.As(err, &noSuchBucket) {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func boolPtrVal(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
