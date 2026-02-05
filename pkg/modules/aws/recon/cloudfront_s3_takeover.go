package recon

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	plugin.Register(&CloudFrontS3TakeoverModule{})
}

// CloudFrontS3TakeoverModule detects CloudFront distributions with S3 origins pointing to non-existent buckets
type CloudFrontS3TakeoverModule struct{}

func (m *CloudFrontS3TakeoverModule) ID() string {
	return "cloudfront-s3-takeover"
}

func (m *CloudFrontS3TakeoverModule) Name() string {
	return "CloudFront S3 Origin Takeover Detection"
}

func (m *CloudFrontS3TakeoverModule) Description() string {
	return "Detects CloudFront distributions with S3 origins pointing to non-existent buckets, which could allow attackers to take over the domain by creating the missing bucket. Also identifies Route53 records pointing to vulnerable distributions."
}

func (m *CloudFrontS3TakeoverModule) Platform() plugin.Platform {
	return plugin.PlatformAWS
}

func (m *CloudFrontS3TakeoverModule) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *CloudFrontS3TakeoverModule) OpsecLevel() string {
	return "safe"
}

func (m *CloudFrontS3TakeoverModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *CloudFrontS3TakeoverModule) References() []string {
	return []string{
		"https://labs.detectify.com/writeups/hostile-subdomain-takeover-using-cloudfront/",
		"https://www.hackerone.com/application-security/guide-subdomain-takeovers",
		"https://github.com/EdOverflow/can-i-take-over-xyz",
	}
}

func (m *CloudFrontS3TakeoverModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "profile",
			Description: "AWS profile name",
			Type:        "string",
		},
		{
			Name:        "profile-dir",
			Description: "AWS profile directory",
			Type:        "string",
		},
	}
}

func (m *CloudFrontS3TakeoverModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	profile, _ := cfg.Args["profile"].(string)
	profileDir, _ := cfg.Args["profile-dir"].(string)

	var opts []*types.Option
	if profileDir != "" {
		opts = append(opts, &types.Option{
			Name:  "profile-dir",
			Value: profileDir,
		})
	}

	// CloudFront is a global service, use us-east-1
	awsCfg, err := helpers.GetAWSCfg("us-east-1", profile, opts, "safe")
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS config: %w", err)
	}

	// Get account ID
	accountID, err := helpers.GetAccountId(awsCfg)
	if err != nil {
		if cfg.Verbose {
			fmt.Fprintf(cfg.Output, "Warning: failed to get account ID: %v\n", err)
		}
		accountID = "unknown"
	}

	// Enumerate CloudFront distributions
	distributions, err := m.enumerateDistributions(cfg.Context, awsCfg, accountID)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate distributions: %w", err)
	}

	if cfg.Verbose {
		fmt.Fprintf(cfg.Output, "Found %d CloudFront distributions\n", len(distributions))
	}

	// Check each distribution for vulnerable S3 origins
	var findings []S3TakeoverFinding
	for _, dist := range distributions {
		if cfg.Verbose {
			fmt.Fprintf(cfg.Output, "Checking distribution %s (%d origins)\n", dist.ID, len(dist.Origins))
		}

		for _, origin := range dist.Origins {
			if origin.OriginType != "s3" {
				continue
			}

			bucketName := m.extractBucketName(origin.DomainName)
			if bucketName == "" {
				if cfg.Verbose {
					fmt.Fprintf(cfg.Output, "Warning: could not extract bucket name from %s\n", origin.DomainName)
				}
				continue
			}

			exists := m.checkBucketExists(cfg.Context, awsCfg, bucketName)
			if !exists {
				if cfg.Verbose {
					fmt.Fprintf(cfg.Output, "VULNERABLE: Distribution %s references non-existent bucket %s\n", dist.ID, bucketName)
				}

				// Find Route53 records pointing to this distribution
				records, err := m.findRoute53Records(cfg.Context, awsCfg, dist.DomainName, dist.Aliases)
				if err != nil && cfg.Verbose {
					fmt.Fprintf(cfg.Output, "Warning: failed to search Route53: %v\n", err)
				}

				// Build finding
				finding := m.buildFinding(dist, origin, bucketName, records)
				findings = append(findings, finding)
			}
		}
	}

	if len(findings) == 0 {
		return []plugin.Result{
			{
				Data: map[string]any{
					"status":  "no_vulnerabilities",
					"message": "No vulnerable CloudFront distributions found",
				},
				Metadata: map[string]any{
					"module":              "cloudfront-s3-takeover",
					"distributions_checked": len(distributions),
				},
			},
		}, nil
	}

	// Return findings
	return []plugin.Result{
		{
			Data: map[string]any{
				"findings": findings,
				"count":    len(findings),
			},
			Metadata: map[string]any{
				"module":      "cloudfront-s3-takeover",
				"platform":    "aws",
				"opsec_level": "safe",
			},
		},
	}, nil
}

// CloudFrontDistributionInfo contains information about a CloudFront distribution
type CloudFrontDistributionInfo struct {
	ID         string       `json:"id"`
	DomainName string       `json:"domain_name"`
	Aliases    []string     `json:"aliases,omitempty"`
	Region     string       `json:"region"`
	AccountID  string       `json:"account_id"`
	Origins    []OriginInfo `json:"origins"`
}

// OriginInfo contains information about a CloudFront origin
type OriginInfo struct {
	ID         string `json:"id"`
	DomainName string `json:"domain_name"`
	OriginType string `json:"origin_type"`
}

// Route53Record contains information about a Route53 record
type Route53Record struct {
	ZoneID     string `json:"zone_id"`
	ZoneName   string `json:"zone_name"`
	RecordName string `json:"record_name"`
	RecordType string `json:"record_type"`
	Value      string `json:"value"`
}

// S3TakeoverFinding contains the complete vulnerability finding
type S3TakeoverFinding struct {
	DistributionID     string          `json:"distribution_id"`
	DistributionDomain string          `json:"distribution_domain"`
	Aliases            []string        `json:"aliases,omitempty"`
	MissingBucket      string          `json:"missing_bucket"`
	OriginDomain       string          `json:"origin_domain"`
	OriginID           string          `json:"origin_id"`
	AccountID          string          `json:"account_id"`
	Region             string          `json:"region"`
	Route53Records     []Route53Record `json:"route53_records,omitempty"`
	AffectedDomains    []string        `json:"affected_domains"`
	Severity           string          `json:"severity"`
	Risk               string          `json:"risk"`
	Remediation        string          `json:"remediation"`
}

func (m *CloudFrontS3TakeoverModule) enumerateDistributions(ctx context.Context, awsCfg aws.Config, accountID string) ([]CloudFrontDistributionInfo, error) {
	client := cloudfront.NewFromConfig(awsCfg)
	var distributions []CloudFrontDistributionInfo

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

			distResult, err := client.GetDistribution(ctx, &cloudfront.GetDistributionInput{
				Id: distSummary.Id,
			})
			if err != nil {
				continue
			}

			if distResult.Distribution == nil || distResult.Distribution.DistributionConfig == nil {
				continue
			}

			dist := distResult.Distribution
			config := dist.DistributionConfig

			info := CloudFrontDistributionInfo{
				ID:         *distSummary.Id,
				DomainName: *distSummary.DomainName,
				Region:     "us-east-1",
				AccountID:  accountID,
			}

			if config.Aliases != nil && config.Aliases.Items != nil {
				info.Aliases = config.Aliases.Items
			}

			if config.Origins != nil && config.Origins.Items != nil {
				for _, origin := range config.Origins.Items {
					if origin.DomainName == nil || origin.Id == nil {
						continue
					}

					originInfo := OriginInfo{
						ID:         *origin.Id,
						DomainName: *origin.DomainName,
					}

					if m.isS3Domain(*origin.DomainName) || origin.S3OriginConfig != nil {
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

func (m *CloudFrontS3TakeoverModule) isS3Domain(domain string) bool {
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

func (m *CloudFrontS3TakeoverModule) checkBucketExists(ctx context.Context, awsCfg aws.Config, bucketName string) bool {
	initialRegion := "us-east-1"
	config, err := helpers.GetAWSCfg(initialRegion, "", nil, "safe")
	if err != nil {
		return true // Assume exists on error to avoid false positives
	}

	s3Client := s3.NewFromConfig(config)

	_, err = s3Client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucketName),
	})

	if err == nil {
		return true
	}

	// Check for NoSuchBucket error
	var noSuchBucket *s3types.NoSuchBucket
	if errors.As(err, &noSuchBucket) {
		return false
	}

	var notFound *s3types.NotFound
	if errors.As(err, &notFound) {
		return false
	}

	errStr := err.Error()

	// Access denied means bucket exists
	if strings.Contains(errStr, "AccessDenied") || strings.Contains(errStr, "Forbidden") || strings.Contains(errStr, "403") {
		return true
	}

	// 404 Not Found means bucket doesn't exist
	if strings.Contains(errStr, "404") || strings.Contains(errStr, "Not Found") {
		return false
	}

	// PermanentRedirect means bucket exists in different region
	if strings.Contains(errStr, "PermanentRedirect") || strings.Contains(errStr, "301") {
		// Try to get the actual region
		bucketRegion := m.extractBucketRegion(err)
		if bucketRegion != "" && bucketRegion != initialRegion {
			// Retry with correct region
			config, err := helpers.GetAWSCfg(bucketRegion, "", nil, "safe")
			if err == nil {
				s3Client := s3.NewFromConfig(config)
				_, err := s3Client.HeadBucket(ctx, &s3.HeadBucketInput{
					Bucket: aws.String(bucketName),
				})
				if err == nil {
					return true
				}
			}
		}
		return true // Assume exists if redirect
	}

	// On unknown errors, assume bucket exists to avoid false positives
	return true
}

func (m *CloudFrontS3TakeoverModule) extractBucketRegion(err error) string {
	var httpErr *awshttp.ResponseError
	if errors.As(err, &httpErr) {
		if httpErr.Response != nil && httpErr.Response.Header != nil {
			if region := httpErr.Response.Header.Get("x-amz-bucket-region"); region != "" {
				return region
			}
		}
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		errStr := apiErr.Error()
		if idx := strings.Index(errStr, "bucket is in '"); idx >= 0 {
			start := idx + len("bucket is in '")
			if endIdx := strings.Index(errStr[start:], "'"); endIdx >= 0 {
				return errStr[start : start+endIdx]
			}
		}
	}

	return ""
}

func (m *CloudFrontS3TakeoverModule) extractBucketName(originDomain string) string {
	domain := strings.TrimPrefix(originDomain, "https://")
	domain = strings.TrimPrefix(domain, "http://")

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

	if idx := strings.Index(domain, ".s3"); idx > 0 {
		return domain[:idx]
	}

	return ""
}

func (m *CloudFrontS3TakeoverModule) findRoute53Records(ctx context.Context, awsCfg aws.Config, cloudfrontDomain string, aliases []string) ([]Route53Record, error) {
	client := route53.NewFromConfig(awsCfg)
	var matchingRecords []Route53Record

	cloudfrontDomain = strings.TrimSuffix(cloudfrontDomain, ".")

	zonesPaginator := route53.NewListHostedZonesPaginator(client, &route53.ListHostedZonesInput{})

	for zonesPaginator.HasMorePages() {
		zonesPage, err := zonesPaginator.NextPage(ctx)
		if err != nil {
			continue
		}

		for _, zone := range zonesPage.HostedZones {
			if zone.Id == nil || zone.Name == nil {
				continue
			}

			zoneID := strings.TrimPrefix(*zone.Id, "/hostedzone/")
			zoneName := strings.TrimSuffix(*zone.Name, ".")

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

					if (recordType == "A" || recordType == "AAAA") && record.AliasTarget != nil {
						if record.AliasTarget.DNSName != nil {
							aliasTarget := strings.TrimSuffix(*record.AliasTarget.DNSName, ".")

							if aliasTarget == cloudfrontDomain {
								matchingRecords = append(matchingRecords, Route53Record{
									ZoneID:     zoneID,
									ZoneName:   zoneName,
									RecordName: recordName,
									RecordType: recordType,
									Value:      aliasTarget,
								})
							}
						}
					}

					if recordType == "CNAME" && record.ResourceRecords != nil {
						for _, rr := range record.ResourceRecords {
							if rr.Value != nil {
								cnameValue := strings.TrimSuffix(*rr.Value, ".")

								if cnameValue == cloudfrontDomain {
									matchingRecords = append(matchingRecords, Route53Record{
										ZoneID:     zoneID,
										ZoneName:   zoneName,
										RecordName: recordName,
										RecordType: recordType,
										Value:      cnameValue,
									})
								}

								for _, alias := range aliases {
									if cnameValue == alias {
										matchingRecords = append(matchingRecords, Route53Record{
											ZoneID:     zoneID,
											ZoneName:   zoneName,
											RecordName: recordName,
											RecordType: recordType,
											Value:      cnameValue,
										})
										break
									}
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

func (m *CloudFrontS3TakeoverModule) buildFinding(dist CloudFrontDistributionInfo, origin OriginInfo, bucketName string, records []Route53Record) S3TakeoverFinding {
	affectedDomains := []string{}
	for _, record := range records {
		affectedDomains = append(affectedDomains, record.RecordName)
	}

	for _, alias := range dist.Aliases {
		found := false
		for _, domain := range affectedDomains {
			if domain == alias {
				found = true
				break
			}
		}
		if !found {
			affectedDomains = append(affectedDomains, alias)
		}
	}

	severity := "MEDIUM"
	riskDescription := fmt.Sprintf("CloudFront distribution %s points to non-existent S3 bucket '%s'. "+
		"An attacker could create this bucket to serve malicious content.",
		dist.ID, bucketName)

	if len(records) > 0 {
		severity = "HIGH"
		riskDescription = fmt.Sprintf("CloudFront distribution %s points to non-existent S3 bucket '%s'. "+
			"Route53 records are actively pointing to this distribution. "+
			"An attacker could create this bucket to serve malicious content on %d domain(s): %s",
			dist.ID, bucketName, len(affectedDomains), strings.Join(affectedDomains, ", "))
	} else if len(affectedDomains) > 0 {
		riskDescription = fmt.Sprintf("CloudFront distribution %s points to non-existent S3 bucket '%s'. "+
			"An attacker could create this bucket to serve malicious content on the following alias domain(s): %s",
			dist.ID, bucketName, strings.Join(affectedDomains, ", "))
	}

	return S3TakeoverFinding{
		DistributionID:     dist.ID,
		DistributionDomain: dist.DomainName,
		Aliases:            dist.Aliases,
		MissingBucket:      bucketName,
		OriginDomain:       origin.DomainName,
		OriginID:           origin.ID,
		AccountID:          dist.AccountID,
		Region:             dist.Region,
		Route53Records:     records,
		AffectedDomains:    affectedDomains,
		Severity:           severity,
		Risk:               riskDescription,
		Remediation: fmt.Sprintf("1. Delete the CloudFront distribution %s if no longer needed, OR\n"+
			"2. Create the S3 bucket '%s' in your account to reclaim ownership, OR\n"+
			"3. Update the distribution to point to a different origin",
			dist.ID, bucketName),
	}
}
