package recon

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestIsS3Domain tests the isS3Domain function with various S3 domain patterns
func TestIsS3Domain(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		// Should return true - standard S3 patterns
		{
			name:     "standard S3 domain",
			domain:   "bucket.s3.amazonaws.com",
			expected: true,
		},
		{
			name:     "S3 with region using dot separator",
			domain:   "bucket.s3.us-east-1.amazonaws.com",
			expected: true,
		},
		{
			name:     "S3 with region using dash separator",
			domain:   "bucket.s3-us-east-1.amazonaws.com",
			expected: true,
		},
		{
			name:     "S3 website endpoint with dot separator",
			domain:   "bucket.s3-website.us-east-1.amazonaws.com",
			expected: true,
		},
		{
			name:     "S3 website endpoint with dash separator",
			domain:   "bucket.s3-website-us-east-1.amazonaws.com",
			expected: true,
		},
		{
			name:     "S3 with any region pattern",
			domain:   "my-data.s3.eu-west-1.amazonaws.com",
			expected: true,
		},
		{
			name:     "S3 path style",
			domain:   "s3.amazonaws.com/my-bucket",
			expected: true,
		},
		{
			name:     "S3 path style with region",
			domain:   "s3.us-west-2.amazonaws.com/my-bucket",
			expected: true,
		},

		// Should return false - non-S3 patterns
		{
			name:     "CloudFront distribution domain",
			domain:   "example.cloudfront.net",
			expected: false,
		},
		{
			name:     "custom domain",
			domain:   "api.example.com",
			expected: false,
		},
		{
			name:     "Google Cloud Storage",
			domain:   "bucket.storage.googleapis.com",
			expected: false,
		},
		{
			name:     "plain website",
			domain:   "www.example.com",
			expected: false,
		},
		{
			name:     "empty string",
			domain:   "",
			expected: false,
		},
		{
			name:     "domain with s3 substring but not S3",
			domain:   "my-s3-backup.example.com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isS3Domain(tt.domain)
			assert.Equal(t, tt.expected, result,
				"isS3Domain(%q) = %v, expected %v", tt.domain, result, tt.expected)
		})
	}
}

// TestExtractBucketName tests the extractBucketName function with various S3 domain patterns
func TestExtractBucketName(t *testing.T) {
	tests := []struct {
		name           string
		originDomain   string
		expectedBucket string
	}{
		// Virtual-hosted style - standard patterns
		{
			name:           "standard S3 domain",
			originDomain:   "my-bucket.s3.amazonaws.com",
			expectedBucket: "my-bucket",
		},
		{
			name:           "S3 with region using dot separator",
			originDomain:   "my-bucket.s3.us-west-2.amazonaws.com",
			expectedBucket: "my-bucket",
		},
		{
			name:           "S3 with region using dash separator",
			originDomain:   "my-bucket.s3-us-west-2.amazonaws.com",
			expectedBucket: "my-bucket",
		},
		{
			name:           "S3 website endpoint with dot separator",
			originDomain:   "my-bucket.s3-website.us-east-1.amazonaws.com",
			expectedBucket: "my-bucket",
		},
		{
			name:           "S3 website endpoint with dash separator",
			originDomain:   "my-bucket.s3-website-us-east-1.amazonaws.com",
			expectedBucket: "my-bucket",
		},
		{
			name:           "bucket with dashes",
			originDomain:   "my-prod-bucket.s3.amazonaws.com",
			expectedBucket: "my-prod-bucket",
		},
		{
			name:           "bucket with multiple parts",
			originDomain:   "my-company-prod-data.s3.eu-west-1.amazonaws.com",
			expectedBucket: "my-company-prod-data",
		},

		// Path-style patterns
		{
			name:           "path style standard",
			originDomain:   "s3.amazonaws.com/my-bucket",
			expectedBucket: "my-bucket",
		},
		{
			name:           "path style with region dot separator",
			originDomain:   "s3.us-west-2.amazonaws.com/my-bucket",
			expectedBucket: "my-bucket",
		},
		{
			name:           "path style with region dash separator",
			originDomain:   "s3-us-west-2.amazonaws.com/my-bucket",
			expectedBucket: "my-bucket",
		},

		// With protocol (should be stripped)
		{
			name:           "https protocol virtual-hosted",
			originDomain:   "https://my-bucket.s3.amazonaws.com",
			expectedBucket: "my-bucket",
		},
		{
			name:           "http protocol virtual-hosted",
			originDomain:   "http://my-bucket.s3.amazonaws.com",
			expectedBucket: "my-bucket",
		},
		{
			name:           "https protocol path-style",
			originDomain:   "https://s3.amazonaws.com/my-bucket",
			expectedBucket: "my-bucket",
		},

		// Edge cases - should return empty string
		{
			name:           "empty string",
			originDomain:   "",
			expectedBucket: "",
		},
		{
			name:           "not an S3 domain",
			originDomain:   "not-an-s3-domain.com",
			expectedBucket: "",
		},
		{
			name:           "CloudFront domain",
			originDomain:   "d111111abcdef8.cloudfront.net",
			expectedBucket: "",
		},
		{
			name:           "custom origin",
			originDomain:   "api.example.com",
			expectedBucket: "",
		},
		{
			name:           "malformed S3-like domain",
			originDomain:   ".s3.amazonaws.com",
			expectedBucket: "",
		},
		{
			name:           "path style missing bucket",
			originDomain:   "s3.amazonaws.com/",
			expectedBucket: "",
		},
		{
			name:           "Google Cloud Storage",
			originDomain:   "bucket.storage.googleapis.com",
			expectedBucket: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractBucketName(tt.originDomain)
			assert.Equal(t, tt.expectedBucket, result,
				"extractBucketName(%q) = %q, expected %q", tt.originDomain, result, tt.expectedBucket)
		})
	}
}

// TestExtractBucketNameRegionVariations tests region variations to ensure proper extraction
func TestExtractBucketNameRegionVariations(t *testing.T) {
	regions := []string{
		"us-east-1",
		"us-east-2",
		"us-west-1",
		"us-west-2",
		"eu-west-1",
		"eu-central-1",
		"ap-southeast-1",
		"ap-northeast-1",
		"sa-east-1",
		"ca-central-1",
	}

	for _, region := range regions {
		t.Run("region_"+region, func(t *testing.T) {
			// Test dot separator
			domainDot := "test-bucket.s3." + region + ".amazonaws.com"
			result := extractBucketName(domainDot)
			assert.Equal(t, "test-bucket", result,
				"Failed to extract bucket from: %s", domainDot)

			// Test dash separator
			domainDash := "test-bucket.s3-" + region + ".amazonaws.com"
			result = extractBucketName(domainDash)
			assert.Equal(t, "test-bucket", result,
				"Failed to extract bucket from: %s", domainDash)

			// Test website endpoint dot separator
			websiteDot := "test-bucket.s3-website." + region + ".amazonaws.com"
			result = extractBucketName(websiteDot)
			assert.Equal(t, "test-bucket", result,
				"Failed to extract bucket from: %s", websiteDot)

			// Test website endpoint dash separator
			websiteDash := "test-bucket.s3-website-" + region + ".amazonaws.com"
			result = extractBucketName(websiteDash)
			assert.Equal(t, "test-bucket", result,
				"Failed to extract bucket from: %s", websiteDash)
		})
	}
}

// TestIsS3DomainEdgeCases tests edge cases for isS3Domain
func TestIsS3DomainEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		{
			name:     "domain with s3 in subdomain but not AWS",
			domain:   "s3.mycompany.com",
			expected: true, // Contains ".s3." pattern
		},
		{
			name:     "domain ending with s3",
			domain:   "backups3",
			expected: false,
		},
		{
			name:     "s3 at start but not S3 domain",
			domain:   "s3backup.example.com",
			expected: false,
		},
		{
			name:     "very long bucket name",
			domain:   "this-is-a-very-long-bucket-name-with-many-hyphens-and-characters.s3.amazonaws.com",
			expected: true,
		},
		{
			name:     "bucket with numbers",
			domain:   "bucket123.s3.amazonaws.com",
			expected: true,
		},
		{
			name:     "bucket with mixed case (should still match)",
			domain:   "MyBucket.s3.amazonaws.com",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isS3Domain(tt.domain)
			assert.Equal(t, tt.expected, result,
				"isS3Domain(%q) = %v, expected %v", tt.domain, result, tt.expected)
		})
	}
}

// TestExtractBucketNameComplexPatterns tests complex bucket name patterns
func TestExtractBucketNameComplexPatterns(t *testing.T) {
	tests := []struct {
		name           string
		originDomain   string
		expectedBucket string
	}{
		{
			name:           "bucket with dots (should work for virtual-hosted)",
			originDomain:   "my.bucket.name.s3.amazonaws.com",
			expectedBucket: "my.bucket.name",
		},
		{
			name:           "very short bucket name",
			originDomain:   "ab.s3.amazonaws.com",
			expectedBucket: "ab",
		},
		{
			name:           "bucket starting with number",
			originDomain:   "123bucket.s3.amazonaws.com",
			expectedBucket: "123bucket",
		},
		{
			name:           "bucket ending with number",
			originDomain:   "bucket123.s3.amazonaws.com",
			expectedBucket: "bucket123",
		},
		{
			name:           "single character bucket",
			originDomain:   "a.s3.amazonaws.com",
			expectedBucket: "a",
		},
		{
			name:           "bucket with underscores (technically invalid but may exist)",
			originDomain:   "my_bucket.s3.amazonaws.com",
			expectedBucket: "my_bucket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractBucketName(tt.originDomain)
			assert.Equal(t, tt.expectedBucket, result,
				"extractBucketName(%q) = %q, expected %q", tt.originDomain, result, tt.expectedBucket)
		})
	}
}
