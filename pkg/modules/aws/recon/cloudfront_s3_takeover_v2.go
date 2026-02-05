package recon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"golang.org/x/sync/errgroup"

	"github.com/praetorian-inc/aurelian/internal/helpers"
)

// CloudFrontS3TakeoverV2 scans for CloudFront distributions with missing S3 origins
type CloudFrontS3TakeoverV2 struct {
	Config aws.Config
}

// CloudFrontDistributionInfoV2 contains information about a CloudFront distribution
type CloudFrontDistributionInfoV2 struct {
	ID         string        `json:"id"`
	DomainName string        `json:"domain_name"`
	Aliases    []string      `json:"aliases,omitempty"`
	Region     string        `json:"region"`
	AccountID  string        `json:"account_id"`
	Origins    []OriginInfoV2 `json:"origins"`
}

// OriginInfoV2 contains information about a CloudFront origin
type OriginInfoV2 struct {
	ID         string `json:"id"`
	DomainName string `json:"domain_name"`
	OriginType string `json:"origin_type"` // "s3", "custom", etc.
}

// VulnerableDistributionV2 contains information about a vulnerable CloudFront distribution
type VulnerableDistributionV2 struct {
	DistributionID     string   `json:"distribution_id"`
	DistributionDomain string   `json:"distribution_domain"`
	Aliases            []string `json:"aliases,omitempty"`
	MissingBucket      string   `json:"missing_bucket"`
	OriginDomain       string   `json:"origin_domain"`
	OriginID           string   `json:"origin_id"`
	AccountID          string   `json:"account_id"`
	Region             string   `json:"region"`
}

// Route53RecordV2 contains information about a Route53 record
type Route53RecordV2 struct {
	ZoneID     string `json:"zone_id"`
	ZoneName   string `json:"zone_name"`
	RecordName string `json:"record_name"`
	RecordType string `json:"record_type"`
	Value      string `json:"value"`
}

// S3TakeoverFindingV2 contains the complete vulnerability finding
type S3TakeoverFindingV2 struct {
	DistributionID     string             `json:"distribution_id"`
	DistributionDomain string             `json:"distribution_domain"`
	Aliases            []string           `json:"aliases,omitempty"`
	MissingBucket      string             `json:"missing_bucket"`
	OriginDomain       string             `json:"origin_domain"`
	OriginID           string             `json:"origin_id"`
	AccountID          string             `json:"account_id"`
	Region             string             `json:"region"`
	Route53Records     []Route53RecordV2  `json:"route53_records,omitempty"`
	AffectedDomains    []string           `json:"affected_domains"`
	Severity           string             `json:"severity"`
	Risk               string             `json:"risk"`
	Remediation        string             `json:"remediation"`
}

// BucketExistenceStateV2 represents the state of bucket existence check
type BucketExistenceStateV2 int

const (
	// BucketExistsV2 means the bucket definitely exists
	BucketExistsV2 BucketExistenceStateV2 = iota
	// BucketNotExistsV2 means the bucket definitely does not exist
	BucketNotExistsV2
	// BucketUnknownV2 means we could not determine if the bucket exists
	BucketUnknownV2
)

// Run executes the CloudFront S3 takeover scan
func (c *CloudFrontS3TakeoverV2) Run(ctx context.Context) ([]S3TakeoverFindingV2, error) {
	// Step 1: Enumerate CloudFront distributions
	distributions, err := c.enumerateDistributions(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate distributions: %w", err)
	}

	slog.Info("enumerated CloudFront distributions", "count", len(distributions))

	// Step 2: Check S3 origins with bounded concurrency
	vulnerableDistributions := []VulnerableDistributionV2{}
	var mu sync.Mutex // Protect vulnerableDistributions slice

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(25) // Bounded concurrency

	for _, dist := range distributions {
		dist := dist // Capture loop variable
		g.Go(func() error {
			vulns := c.checkDistributionOrigins(gctx, dist)
			if len(vulns) > 0 {
				mu.Lock()
				vulnerableDistributions = append(vulnerableDistributions, vulns...)
				mu.Unlock()
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, fmt.Errorf("error checking origins: %w", err)
	}

	slog.Info("found vulnerable distributions", "count", len(vulnerableDistributions))

	// Step 3: Find Route53 records for vulnerable distributions
	findings := []S3TakeoverFindingV2{}
	for _, vuln := range vulnerableDistributions {
		finding, err := c.enrichWithRoute53(ctx, vuln)
		if err != nil {
			slog.Warn("failed to enrich with route53 data", "distribution_id", vuln.DistributionID, "error", err)
			// Still add the finding without Route53 data
			finding = c.createFinding(vuln, []Route53RecordV2{})
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

// enumerateDistributions lists all CloudFront distributions
func (c *CloudFrontS3TakeoverV2) enumerateDistributions(ctx context.Context) ([]CloudFrontDistributionInfoV2, error) {
	// CloudFront is a global service, always use us-east-1
	client := cloudfront.NewFromConfig(c.Config)

	accountID, err := helpers.GetAccountId(c.Config)
	if err != nil {
		slog.Warn("failed to get account ID", "error", err)
		accountID = "unknown"
	}

	distributions := []CloudFrontDistributionInfoV2{}

	paginator := cloudfront.NewListDistributionsPaginator(client, &cloudfront.ListDistributionsInput{}, func(o *cloudfront.ListDistributionsPaginatorOptions) {
		o.Limit = 1000
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list distributions: %w", err)
		}

		if page.DistributionList == nil || page.DistributionList.Items == nil {
			continue
		}

		for _, distSummary := range page.DistributionList.Items {
			if distSummary.Id == nil {
				continue
			}

			// Get detailed distribution config
			distResult, err := client.GetDistribution(ctx, &cloudfront.GetDistributionInput{
				Id: distSummary.Id,
			})
			if err != nil {
				slog.Error("failed to get distribution details", "id", *distSummary.Id, "error", err)
				continue
			}

			if distResult.Distribution == nil || distResult.Distribution.DistributionConfig == nil {
				continue
			}

			dist := distResult.Distribution
			config := dist.DistributionConfig

			// Build distribution info
			info := CloudFrontDistributionInfoV2{
				ID:         *distSummary.Id,
				DomainName: *distSummary.DomainName,
				Region:     "us-east-1",
				AccountID:  accountID,
			}

			// Get aliases
			if config.Aliases != nil && config.Aliases.Items != nil {
				info.Aliases = config.Aliases.Items
			}

			// Get origins
			if config.Origins != nil && config.Origins.Items != nil {
				for _, origin := range config.Origins.Items {
					if origin.DomainName == nil || origin.Id == nil {
						continue
					}

					originInfo := OriginInfoV2{
						ID:         *origin.Id,
						DomainName: *origin.DomainName,
					}

					// Determine origin type
					domainName := *origin.DomainName
					if isS3Domain(domainName) {
						originInfo.OriginType = "s3"
					} else if origin.S3OriginConfig != nil {
						originInfo.OriginType = "s3"
					} else {
						originInfo.OriginType = "custom"
					}

					info.Origins = append(info.Origins, originInfo)
				}
			}

			distributions = append(distributions, info)
		}
	}

	return distributions, nil
}

// checkDistributionOrigins checks if S3 origins exist for a distribution
func (c *CloudFrontS3TakeoverV2) checkDistributionOrigins(ctx context.Context, dist CloudFrontDistributionInfoV2) []VulnerableDistributionV2 {
	vulnerableDistributions := []VulnerableDistributionV2{}

	for _, origin := range dist.Origins {
		if origin.OriginType != "s3" {
			continue
		}

		bucketName := extractBucketName(origin.DomainName)
		if bucketName == "" {
			slog.Warn("could not extract bucket name", "distribution_id", dist.ID, "origin_domain", origin.DomainName)
			continue
		}

		state := c.checkBucketExists(ctx, bucketName)

		if state == BucketNotExistsV2 {
			slog.Warn("found vulnerable distribution with missing bucket", "distribution_id", dist.ID, "bucket", bucketName)
			vulnerableDistributions = append(vulnerableDistributions, VulnerableDistributionV2{
				DistributionID:     dist.ID,
				DistributionDomain: dist.DomainName,
				Aliases:            dist.Aliases,
				MissingBucket:      bucketName,
				OriginDomain:       origin.DomainName,
				OriginID:           origin.ID,
				AccountID:          dist.AccountID,
				Region:             dist.Region,
			})
		}
	}

	return vulnerableDistributions
}

// checkBucketExists checks if an S3 bucket exists
func (c *CloudFrontS3TakeoverV2) checkBucketExists(ctx context.Context, bucketName string) BucketExistenceStateV2 {
	// Start with us-east-1 as it's the default region for many buckets
	initialRegion := "us-east-1"

	// Create S3 client with specific region
	regionalConfig := c.Config.Copy()
	regionalConfig.Region = initialRegion
	s3Client := s3.NewFromConfig(regionalConfig)

	// First attempt with HeadBucket
	_, err := s3Client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucketName),
	})

	if err == nil {
		return BucketExistsV2
	}

	// Analyze the error
	state, shouldRetryInDifferentRegion := analyzeS3Error(err, bucketName, initialRegion)

	if !shouldRetryInDifferentRegion {
		return state
	}

	// Try to determine the actual bucket region
	bucketRegion := extractBucketRegion(err, bucketName)

	if bucketRegion == "" {
		// Try GetBucketLocation as fallback
		bucketRegion = c.getBucketRegionViaAPI(ctx, bucketName, initialRegion)
	}

	if bucketRegion == "" || bucketRegion == initialRegion {
		return BucketUnknownV2
	}

	// Retry with detected region
	regionalConfig.Region = bucketRegion
	s3Client = s3.NewFromConfig(regionalConfig)

	_, err = s3Client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucketName),
	})

	if err == nil {
		return BucketExistsV2
	}

	// Analyze the error from the correct region
	finalState, _ := analyzeS3Error(err, bucketName, bucketRegion)
	return finalState
}

// analyzeS3Error analyzes an S3 error and returns the bucket state
func analyzeS3Error(err error, bucketName string, region string) (BucketExistenceStateV2, bool) {
	// Check for NoSuchBucket error
	var noSuchBucket *s3types.NoSuchBucket
	if errors.As(err, &noSuchBucket) {
		return BucketNotExistsV2, false
	}

	// Check for NotFound error
	var notFound *s3types.NotFound
	if errors.As(err, &notFound) {
		return BucketNotExistsV2, false
	}

	// Get the error string for pattern matching
	errStr := err.Error()

	// Check for access denied - bucket exists but we can't access it
	if strings.Contains(errStr, "AccessDenied") || strings.Contains(errStr, "Forbidden") || strings.Contains(errStr, "403") {
		return BucketExistsV2, false
	}

	// Check for permanent redirect - bucket is in a different region
	if strings.Contains(errStr, "PermanentRedirect") || strings.Contains(errStr, "301") {
		return BucketUnknownV2, true // Should retry with different region
	}

	// Check for 404 Not Found
	if strings.Contains(errStr, "404") || strings.Contains(errStr, "Not Found") {
		return BucketNotExistsV2, false
	}

	// Log unexpected error
	slog.Warn("unexpected error checking bucket existence", "bucket", bucketName, "region", region, "error", err)

	return BucketUnknownV2, false
}

// extractBucketRegion tries to extract the bucket region from error response headers
func extractBucketRegion(err error, bucketName string) string {
	// Try to extract response from smithy error
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		// Try to get the HTTP response
		var httpErr *awshttp.ResponseError
		if errors.As(err, &httpErr) {
			if httpErr.Response != nil && httpErr.Response.Header != nil {
				// Look for x-amz-bucket-region header
				if region := httpErr.Response.Header.Get("x-amz-bucket-region"); region != "" {
					return region
				}
			}
		}
	}

	// Try to parse region from error message
	errStr := err.Error()
	// Look for patterns like "bucket is in 'us-west-2' region"
	if idx := strings.Index(errStr, "bucket is in '"); idx >= 0 {
		start := idx + len("bucket is in '")
		if endIdx := strings.Index(errStr[start:], "'"); endIdx >= 0 {
			return errStr[start : start+endIdx]
		}
	}

	return ""
}

// getBucketRegionViaAPI tries to get bucket region using GetBucketLocation API
func (c *CloudFrontS3TakeoverV2) getBucketRegionViaAPI(ctx context.Context, bucketName string, initialRegion string) string {
	// Create S3 client with specific region
	regionalConfig := c.Config.Copy()
	regionalConfig.Region = initialRegion
	s3Client := s3.NewFromConfig(regionalConfig)

	locationResp, err := s3Client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{
		Bucket: aws.String(bucketName),
	})

	if err != nil {
		return ""
	}

	// Handle empty LocationConstraint (means us-east-1)
	bucketRegion := "us-east-1"
	if locationResp.LocationConstraint != "" {
		bucketRegion = string(locationResp.LocationConstraint)
	}

	return bucketRegion
}

// enrichWithRoute53 finds Route53 records pointing to a vulnerable distribution
func (c *CloudFrontS3TakeoverV2) enrichWithRoute53(ctx context.Context, vuln VulnerableDistributionV2) (S3TakeoverFindingV2, error) {
	// Route53 is a global service, use us-east-1
	regionalConfig := c.Config.Copy()
	regionalConfig.Region = "us-east-1"
	route53Client := route53.NewFromConfig(regionalConfig)

	records, err := c.findRoute53Records(ctx, route53Client, vuln.DistributionDomain, vuln.Aliases)
	if err != nil {
		return S3TakeoverFindingV2{}, fmt.Errorf("failed to find route53 records: %w", err)
	}

	return c.createFinding(vuln, records), nil
}

// findRoute53Records finds all Route53 records pointing to a CloudFront distribution
func (c *CloudFrontS3TakeoverV2) findRoute53Records(ctx context.Context, client *route53.Client, cloudfrontDomain string, aliases []string) ([]Route53RecordV2, error) {
	var matchingRecords []Route53RecordV2

	// Normalize CloudFront domain
	cloudfrontDomain = strings.TrimSuffix(cloudfrontDomain, ".")

	// Get all hosted zones
	zonesPaginator := route53.NewListHostedZonesPaginator(client, &route53.ListHostedZonesInput{})

	for zonesPaginator.HasMorePages() {
		zonesPage, err := zonesPaginator.NextPage(ctx)
		if err != nil {
			slog.Warn("failed to list hosted zones", "error", err)
			continue
		}

		for _, zone := range zonesPage.HostedZones {
			if zone.Id == nil || zone.Name == nil {
				continue
			}

			zoneID := strings.TrimPrefix(*zone.Id, "/hostedzone/")
			zoneName := strings.TrimSuffix(*zone.Name, ".")

			// Get all records in this zone
			recordsPaginator := route53.NewListResourceRecordSetsPaginator(client, &route53.ListResourceRecordSetsInput{
				HostedZoneId: &zoneID,
			})

			for recordsPaginator.HasMorePages() {
				recordsPage, err := recordsPaginator.NextPage(ctx)
				if err != nil {
					continue
				}

				for _, record := range recordsPage.ResourceRecordSets {
					if record.Name == nil {
						continue
					}

					recordName := strings.TrimSuffix(*record.Name, ".")
					recordType := string(record.Type)

					// Check A and AAAA records with alias targets
					if (recordType == "A" || recordType == "AAAA") && record.AliasTarget != nil {
						if record.AliasTarget.DNSName != nil {
							aliasTarget := strings.TrimSuffix(*record.AliasTarget.DNSName, ".")

							if aliasTarget == cloudfrontDomain {
								matchingRecords = append(matchingRecords, Route53RecordV2{
									ZoneID:     zoneID,
									ZoneName:   zoneName,
									RecordName: recordName,
									RecordType: recordType,
									Value:      aliasTarget,
								})
							}
						}
					}

					// Check CNAME records
					if recordType == "CNAME" && record.ResourceRecords != nil {
						for _, rr := range record.ResourceRecords {
							if rr.Value != nil {
								cnameValue := strings.TrimSuffix(*rr.Value, ".")

								if cnameValue == cloudfrontDomain || slices.Contains(aliases, cnameValue) {
									matchingRecords = append(matchingRecords, Route53RecordV2{
										ZoneID:     zoneID,
										ZoneName:   zoneName,
										RecordName: recordName,
										RecordType: recordType,
										Value:      cnameValue,
									})
								}
							}
						}
					}
				}
			}
		}
	}

	return matchingRecords, nil
}

// createFinding creates the final finding with severity and risk assessment
func (c *CloudFrontS3TakeoverV2) createFinding(vuln VulnerableDistributionV2, records []Route53RecordV2) S3TakeoverFindingV2 {
	// Build affected domains list
	affectedDomains := []string{}
	for _, record := range records {
		affectedDomains = append(affectedDomains, record.RecordName)
	}

	// Add aliases as potentially affected domains
	for _, alias := range vuln.Aliases {
		if !slices.Contains(affectedDomains, alias) {
			affectedDomains = append(affectedDomains, alias)
		}
	}

	// Set severity and risk based on whether Route53 records were found
	severity := "MEDIUM"
	riskDescription := fmt.Sprintf("CloudFront distribution %s points to non-existent S3 bucket '%s'. "+
		"An attacker could create this bucket to serve malicious content.",
		vuln.DistributionID, vuln.MissingBucket)

	if len(records) > 0 {
		severity = "HIGH"
		riskDescription = fmt.Sprintf("CloudFront distribution %s points to non-existent S3 bucket '%s'. "+
			"Route53 records are actively pointing to this distribution. "+
			"An attacker could create this bucket to serve malicious content on %d domain(s): %s",
			vuln.DistributionID, vuln.MissingBucket, len(affectedDomains), strings.Join(affectedDomains, ", "))
	} else if len(affectedDomains) > 0 {
		riskDescription = fmt.Sprintf("CloudFront distribution %s points to non-existent S3 bucket '%s'. "+
			"An attacker could create this bucket to serve malicious content on the following alias domain(s): %s",
			vuln.DistributionID, vuln.MissingBucket, strings.Join(affectedDomains, ", "))
	}

	return S3TakeoverFindingV2{
		DistributionID:     vuln.DistributionID,
		DistributionDomain: vuln.DistributionDomain,
		Aliases:            vuln.Aliases,
		MissingBucket:      vuln.MissingBucket,
		OriginDomain:       vuln.OriginDomain,
		OriginID:           vuln.OriginID,
		AccountID:          vuln.AccountID,
		Region:             vuln.Region,
		Route53Records:     records,
		AffectedDomains:    affectedDomains,
		Severity:           severity,
		Risk:               riskDescription,
		Remediation: fmt.Sprintf("1. Delete the CloudFront distribution %s if no longer needed, OR\n"+
			"2. Create the S3 bucket '%s' in your account to reclaim ownership, OR\n"+
			"3. Update the distribution to point to a different origin",
			vuln.DistributionID, vuln.MissingBucket),
	}
}

// isS3Domain checks if a domain looks like an S3 domain
func isS3Domain(domain string) bool {
	// Check for various S3 domain patterns
	patterns := []string{
		".s3.amazonaws.com",
		".s3-website.",
		".s3-website-",
		".s3-",
		".s3.",
	}

	for _, pattern := range patterns {
		if strings.Contains(domain, pattern) {
			return true
		}
	}

	return false
}

// extractBucketName extracts the bucket name from an S3 domain
func extractBucketName(originDomain string) string {
	// Remove protocol if present
	domain := strings.TrimPrefix(originDomain, "https://")
	domain = strings.TrimPrefix(domain, "http://")

	// Virtual-hosted style patterns (bucket name is first part)
	virtualPatterns := []struct {
		pattern string
		index   int
	}{
		{`^([^.]+)\.s3\.amazonaws\.com`, 1},
		{`^([^.]+)\.s3\.([a-z0-9-]+)\.amazonaws\.com`, 1},
		{`^([^.]+)\.s3-([a-z0-9-]+)\.amazonaws\.com`, 1},
		{`^([^.]+)\.s3-website\.([a-z0-9-]+)\.amazonaws\.com`, 1},
		{`^([^.]+)\.s3-website-([a-z0-9-]+)\.amazonaws\.com`, 1},
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
		{`^s3\.([a-z0-9-]+)\.amazonaws\.com/([^/]+)`, 2},
		{`^s3-([a-z0-9-]+)\.amazonaws\.com/([^/]+)`, 2},
	}

	for _, p := range pathPatterns {
		re := regexp.MustCompile(p.pattern)
		matches := re.FindStringSubmatch(domain)
		if len(matches) > p.index {
			return matches[p.index]
		}
	}

	// If no pattern matches, try simple heuristic
	if idx := strings.Index(domain, ".s3"); idx > 0 {
		return domain[:idx]
	}

	return ""
}
