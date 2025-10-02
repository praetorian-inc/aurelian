package cloudfront

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
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
		slog.Debug("Skipping non-CloudFront distribution info")
		return nil
	}

	slog.Debug("Checking S3 origins for distribution", "id", distInfo.ID, "origins", len(distInfo.Origins))

	// Check each S3 origin
	for _, origin := range distInfo.Origins {
		if origin.OriginType != "s3" {
			continue
		}

		bucketName := extractBucketName(origin.DomainName)
		if bucketName == "" {
			slog.Warn("Could not extract bucket name from S3 origin",
				"distribution_id", distInfo.ID,
				"origin", origin.DomainName)
			continue
		}

		slog.Debug("Checking S3 bucket existence",
			"distribution_id", distInfo.ID,
			"bucket", bucketName,
			"origin", origin.DomainName)

		exists, err := c.checkBucketExists(bucketName)
		if err != nil {
			slog.Warn("Error checking bucket existence",
				"bucket", bucketName,
				"error", err)
			// Continue checking other buckets
			continue
		}

		if !exists {
			slog.Info("VULNERABLE: Found CloudFront distribution with non-existent S3 bucket",
				"distribution_id", distInfo.ID,
				"distribution_domain", distInfo.DomainName,
				"missing_bucket", bucketName,
				"origin_domain", origin.DomainName)

			// Create vulnerability finding
			vuln := VulnerableDistribution{
				DistributionID:     distInfo.ID,
				DistributionDomain: distInfo.DomainName,
				Aliases:            distInfo.Aliases,
				MissingBucket:      bucketName,
				OriginDomain:       origin.DomainName,
				OriginID:           origin.ID,
				AccountID:          distInfo.AccountID,
				Region:             distInfo.Region,
				Severity:           "HIGH",
				Risk: fmt.Sprintf("CloudFront distribution %s points to non-existent S3 bucket '%s'. "+
					"An attacker could create this bucket to serve malicious content on your domain.",
					distInfo.ID, bucketName),
			}

			// Send vulnerability to next link
			if err := c.Send(vuln); err != nil {
				return err
			}
		} else {
			slog.Debug("S3 bucket exists",
				"distribution_id", distInfo.ID,
				"bucket", bucketName)
		}
	}

	return nil
}

// checkBucketExists checks if an S3 bucket exists
func (c *CloudFrontS3OriginChecker) checkBucketExists(bucketName string) (bool, error) {
	// Try multiple regions as bucket could be in any region
	regions := []string{"us-east-1", "us-west-2", "eu-west-1", "ap-northeast-1"}

	for _, region := range regions {
		config, err := c.GetConfigWithRuntimeArgs(region)
		if err != nil {
			continue
		}

		s3Client := s3.NewFromConfig(config)

		// Use HeadBucket to check if bucket exists
		_, err = s3Client.HeadBucket(context.TODO(), &s3.HeadBucketInput{
			Bucket: &bucketName,
		})

		if err == nil {
			// Bucket exists and we have access
			return true, nil
		}

		// Check the error type
		var noSuchBucket *s3types.NoSuchBucket
		if errors.As(err, &noSuchBucket) {
			// Bucket definitely does not exist
			return false, nil
		}

		// Check for access denied - bucket exists but we can't access it
		errStr := err.Error()
		if strings.Contains(errStr, "AccessDenied") || strings.Contains(errStr, "Forbidden") {
			// Bucket exists but we don't have access (not a takeover risk)
			return true, nil
		}

		if strings.Contains(errStr, "PermanentRedirect") || strings.Contains(errStr, "301") {
			// Bucket exists in a different region, try next region
			continue
		}

		// Some other error, log and continue
		slog.Debug("Unexpected error checking bucket",
			"bucket", bucketName,
			"error", err)
		continue
	}

	// If we couldn't determine in any region, assume it doesn't exist (conservative approach)
	return false, nil
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
	// - s3.amazonaws.com/bucket-name (path-style, older)

	patterns := []string{
		`^([^.]+)\.s3\.amazonaws\.com`,
		`^([^.]+)\.s3\.([a-z0-9-]+)\.amazonaws\.com`,
		`^([^.]+)\.s3-([a-z0-9-]+)\.amazonaws\.com`,
		`^s3\.amazonaws\.com/([^/]+)`,
		`^s3\.([a-z0-9-]+)\.amazonaws\.com/([^/]+)`,
		`^s3-([a-z0-9-]+)\.amazonaws\.com/([^/]+)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(domain)
		if len(matches) > 1 {
			// Return the first captured group (bucket name)
			return matches[1]
		}
		// For path-style URLs, bucket name might be in the last captured group
		if len(matches) > 2 && matches[2] != "" && !strings.Contains(matches[2], "-") {
			return matches[2]
		}
	}

	// If no pattern matches, try simple heuristic
	// Check if it looks like bucket.s3* pattern
	if idx := strings.Index(domain, ".s3"); idx > 0 {
		return domain[:idx]
	}

	return ""
}
