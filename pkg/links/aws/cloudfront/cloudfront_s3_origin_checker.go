package cloudfront

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
)

// BucketExistenceState represents the state of bucket existence check
type BucketExistenceState int

const (
	// BucketExists means the bucket definitely exists
	BucketExists BucketExistenceState = iota
	// BucketNotExists means the bucket definitely does not exist
	BucketNotExists
	// BucketUnknown means we could not determine if the bucket exists
	BucketUnknown
)

// CloudFrontS3OriginChecker checks if S3 buckets referenced in CloudFront origins exist
type CloudFrontS3OriginChecker struct {
	*base.AwsReconLink
}

// VulnerableDistribution contains information about a vulnerable CloudFront distribution
type VulnerableDistribution struct {
	DistributionID     string   `json:"distribution_id"`
	DistributionDomain string   `json:"distribution_domain"`
	Aliases            []string `json:"aliases,omitempty"`
	MissingBucket      string   `json:"missing_bucket"`
	OriginDomain       string   `json:"origin_domain"`
	OriginID           string   `json:"origin_id"`
	AccountID          string   `json:"account_id"`
	Region             string   `json:"region"`
	Severity           string   `json:"severity"`
	Risk               string   `json:"risk"`
}

// NewCloudFrontS3OriginChecker creates a new S3 origin checker
func NewCloudFrontS3OriginChecker(configs ...cfg.Config) chain.Link {
	checker := &CloudFrontS3OriginChecker{}
	checker.AwsReconLink = base.NewAwsReconLink(checker, configs...)
	return checker
}

// Process checks if S3 origins exist
func (c *CloudFrontS3OriginChecker) Process(resource any) error {
	distInfo, ok := resource.(CloudFrontDistributionInfo)
	if !ok {
		message.Info("Skipping non-CloudFront distribution info")
		return nil
	}

	message.Info("Checking S3 origins for distribution %s (%d origins)", distInfo.ID, len(distInfo.Origins))

	// Check each S3 origin
	for _, origin := range distInfo.Origins {
		if origin.OriginType != "s3" {
			continue
		}

		bucketName := extractBucketName(origin.DomainName)
		if bucketName == "" {
			message.Warning("Could not extract bucket name from S3 origin for distribution %s: %s",
				distInfo.ID, origin.DomainName)
			continue
		}

		message.Info("Checking S3 bucket existence for distribution %s, bucket '%s', origin %s",
			distInfo.ID, bucketName, origin.DomainName)

		state := c.checkBucketExists(bucketName)

		switch state {
		case BucketNotExists:
			message.Warning("VULNERABLE: Found CloudFront distribution %s with non-existent S3 bucket '%s' (domain: %s, origin: %s)",
				distInfo.ID, bucketName, distInfo.DomainName, origin.DomainName)

			// Create vulnerability finding as VulnerableDistribution for Route53 finder
			vuln := VulnerableDistribution{
				DistributionID:     distInfo.ID,
				DistributionDomain: distInfo.DomainName,
				Aliases:            distInfo.Aliases,
				MissingBucket:      bucketName,
				OriginDomain:       origin.DomainName,
				OriginID:           origin.ID,
				AccountID:          distInfo.AccountID,
				Region:             distInfo.Region,
				Severity:           "MEDIUM",
				Risk: fmt.Sprintf("CloudFront distribution %s points to non-existent S3 bucket '%s'. "+
					"An attacker could create this bucket to serve malicious content on your domain.",
					distInfo.ID, bucketName),
			}

			// Send vulnerability to next link in chain
			if err := c.Send(vuln); err != nil {
				return err
			}

		case BucketExists:
			message.Info("S3 bucket '%s' exists for distribution %s", bucketName, distInfo.ID)

		case BucketUnknown:
			message.Warning("Could not determine S3 bucket existence state for distribution %s, bucket '%s': Unable to confirm if bucket exists or not due to network/permission issues",
				distInfo.ID, bucketName)
			// Don't report as vulnerable since we're not sure
		}
	}

	return nil
}

// checkBucketExists checks if an S3 bucket exists
func (c *CloudFrontS3OriginChecker) checkBucketExists(bucketName string) BucketExistenceState {
	ctx := context.TODO()

	// Start with us-east-1 as it's the default region for many buckets
	initialRegion := "us-east-1"

	config, err := c.GetConfigWithRuntimeArgs(initialRegion)
	if err != nil {
		message.Error("Failed to get AWS config for bucket %s in region %s: %v",
			bucketName, initialRegion, err)
		return BucketUnknown
	}

	s3Client := s3.NewFromConfig(config)

	// First attempt with HeadBucket
	_, err = s3Client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucketName),
	})

	if err == nil {
		message.Info("Bucket '%s' exists and is accessible in region %s", bucketName, initialRegion)
		return BucketExists
	}

	// Analyze the error
	state, shouldRetryInDifferentRegion := c.analyzeS3Error(err, bucketName, initialRegion)

	if !shouldRetryInDifferentRegion {
		return state
	}

	// Try to determine the actual bucket region
	bucketRegion := c.extractBucketRegion(err, bucketName, initialRegion)

	if bucketRegion == "" {
		// Try GetBucketLocation as fallback
		bucketRegion = c.getBucketRegionViaAPI(bucketName, initialRegion)
	}

	if bucketRegion == "" || bucketRegion == initialRegion {
		message.Warning("Could not determine bucket region after PermanentRedirect for bucket %s (initial region: %s)",
			bucketName, initialRegion)
		return BucketUnknown
	}

	message.Info("Retrying bucket check for '%s' with detected region %s", bucketName, bucketRegion)

	config, err = c.GetConfigWithRuntimeArgs(bucketRegion)
	if err != nil {
		message.Error("Failed to get AWS config for detected region %s, bucket %s: %v",
			bucketRegion, bucketName, err)
		return BucketUnknown
	}

	s3Client = s3.NewFromConfig(config)
	_, err = s3Client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucketName),
	})

	if err == nil {
		message.Info("Bucket '%s' exists in different region %s", bucketName, bucketRegion)
		return BucketExists
	}

	// Analyze the error from the correct region
	finalState, _ := c.analyzeS3Error(err, bucketName, bucketRegion)
	return finalState
}

// analyzeS3Error analyzes an S3 error and returns the bucket state
func (c *CloudFrontS3OriginChecker) analyzeS3Error(err error, bucketName string, region string) (BucketExistenceState, bool) {
	// Check for NoSuchBucket error
	var noSuchBucket *s3types.NoSuchBucket
	if errors.As(err, &noSuchBucket) {
		message.Info("Bucket '%s' does not exist in region %s", bucketName, region)
		return BucketNotExists, false
	}

	// Check for NotFound error
	var notFound *s3types.NotFound
	if errors.As(err, &notFound) {
		message.Info("Bucket '%s' not found in region %s", bucketName, region)
		return BucketNotExists, false
	}

	// Get the error string for pattern matching
	errStr := err.Error()

	// Check for access denied - bucket exists but we can't access it
	if strings.Contains(errStr, "AccessDenied") || strings.Contains(errStr, "Forbidden") || strings.Contains(errStr, "403") {
		message.Info("Bucket '%s' exists but access is denied in region %s", bucketName, region)
		return BucketExists, false
	}

	// Check for permanent redirect - bucket is in a different region
	if strings.Contains(errStr, "PermanentRedirect") || strings.Contains(errStr, "301") {
		message.Info("Bucket '%s' exists in a different region (attempted region: %s)", bucketName, region)
		return BucketUnknown, true // Should retry with different region
	}

	// Check for 404 Not Found
	if strings.Contains(errStr, "404") || strings.Contains(errStr, "Not Found") {
		message.Info("Bucket '%s' does not exist (404) in region %s", bucketName, region)
		return BucketNotExists, false
	}

	// Log unexpected error
	message.Warning("Unexpected error checking bucket %s existence in region %s: %v (type: %T)",
		bucketName, region, err, err)

	return BucketUnknown, false
}

// extractBucketRegion tries to extract the bucket region from error response headers
func (c *CloudFrontS3OriginChecker) extractBucketRegion(err error, bucketName string, attemptedRegion string) string {
	// Try to extract response from smithy error
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		// Try to get the HTTP response
		var httpErr *awshttp.ResponseError
		if errors.As(err, &httpErr) {
			if httpErr.Response != nil && httpErr.Response.Header != nil {
				// Look for x-amz-bucket-region header
				if region := httpErr.Response.Header.Get("x-amz-bucket-region"); region != "" {
					message.Info("Found bucket region for '%s' in response header: %s", bucketName, region)
					return region
				}
			}
		}
	}

	// Try to parse region from error message (some errors include the region)
	errStr := err.Error()
	// Look for patterns like "bucket is in 'us-west-2' region"
	if idx := strings.Index(errStr, "bucket is in '"); idx >= 0 {
		start := idx + len("bucket is in '")
		if endIdx := strings.Index(errStr[start:], "'"); endIdx >= 0 {
			region := errStr[start : start+endIdx]
			message.Info("Extracted bucket region for '%s' from error message: %s", bucketName, region)
			return region
		}
	}

	return ""
}

// getBucketRegionViaAPI tries to get bucket region using GetBucketLocation API
func (c *CloudFrontS3OriginChecker) getBucketRegionViaAPI(bucketName string, initialRegion string) string {
	ctx := context.TODO()

	// GetBucketLocation often works from us-east-1 even for buckets in other regions
	config, err := c.GetConfigWithRuntimeArgs(initialRegion)
	if err != nil {
		message.Info("Failed to get AWS config for GetBucketLocation for bucket '%s': %v", bucketName, err)
		return ""
	}

	s3Client := s3.NewFromConfig(config)

	locationResp, err := s3Client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
		Bucket: aws.String(bucketName),
	})

	if err != nil {
		// Check if it's an access issue vs bucket not existing
		errStr := err.Error()
		if strings.Contains(errStr, "NoSuchBucket") || strings.Contains(errStr, "NotFound") {
			message.Info("GetBucketLocation confirms bucket '%s' does not exist", bucketName)
		} else {
			message.Info("GetBucketLocation failed for bucket '%s': %v", bucketName, err)
		}
		return ""
	}

	// Handle empty LocationConstraint (means us-east-1)
	bucketRegion := "us-east-1"
	if locationResp.LocationConstraint != "" {
		bucketRegion = string(locationResp.LocationConstraint)
	}

	message.Info("Determined bucket region for '%s' via GetBucketLocation: %s", bucketName, bucketRegion)

	return bucketRegion
}

// extractBucketName extracts the bucket name from an S3 domain
func extractBucketName(originDomain string) string {
	// Remove protocol if present
	domain := strings.TrimPrefix(originDomain, "https://")
	domain = strings.TrimPrefix(domain, "http://")

	// Patterns for S3 origins:
	// - bucket-name.s3.amazonaws.com
	// - bucket-name.s3.region.amazonaws.com
	// - bucket-name.s3-region.amazonaws.com
	// - bucket-name.s3-website.region.amazonaws.com (S3 website endpoints)
	// - bucket-name.s3-website-region.amazonaws.com (S3 website endpoints)
	// - s3.amazonaws.com/bucket-name (path-style, older)

	// Virtual-hosted style patterns (bucket name is first part)
	virtualPatterns := []struct {
		pattern string
		index   int
	}{
		{`^([^.]+)\.s3\.amazonaws\.com`, 1},
		{`^([^.]+)\.s3\.([a-z0-9-]+)\.amazonaws\.com`, 1},
		{`^([^.]+)\.s3-([a-z0-9-]+)\.amazonaws\.com`, 1},
		{`^([^.]+)\.s3-website\.([a-z0-9-]+)\.amazonaws\.com`, 1}, // S3 website endpoint
		{`^([^.]+)\.s3-website-([a-z0-9-]+)\.amazonaws\.com`, 1},  // S3 website endpoint with dash
	}

	for _, p := range virtualPatterns {
		re := regexp.MustCompile(p.pattern)
		matches := re.FindStringSubmatch(domain)
		if len(matches) > p.index {
			return matches[p.index]
		}
	}

	// Path-style patterns (bucket name comes after the domain)
	pathPatterns := []struct {
		pattern string
		index   int
	}{
		{`^s3\.amazonaws\.com/([^/]+)`, 1},
		{`^s3\.([a-z0-9-]+)\.amazonaws\.com/([^/]+)`, 2}, // Region is first group, bucket is second
		{`^s3-([a-z0-9-]+)\.amazonaws\.com/([^/]+)`, 2},  // Region is first group, bucket is second
	}

	for _, p := range pathPatterns {
		re := regexp.MustCompile(p.pattern)
		matches := re.FindStringSubmatch(domain)
		if len(matches) > p.index {
			return matches[p.index]
		}
	}

	// If no pattern matches, try simple heuristic
	// Check if it looks like bucket.s3* pattern
	if idx := strings.Index(domain, ".s3"); idx > 0 {
		return domain[:idx]
	}

	return ""
}
