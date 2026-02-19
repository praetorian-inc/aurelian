package cloudfront

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	helpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

// Scan detects CloudFront distributions with S3 origins pointing to non-existent
// buckets. It enumerates distributions, checks bucket existence, queries Route53
// for pointing records, and returns Risk findings.
func Scan(ctx context.Context, opts ScanOptions) (ScanResult, error) {
	// CloudFront is a global service — always use us-east-1
	awsCfg, err := helpers.NewAWSConfig(helpers.AWSConfigInput{
		Region:     "us-east-1",
		Profile:    opts.Profile,
		ProfileDir: opts.ProfileDir,
	})
	if err != nil {
		return ScanResult{}, fmt.Errorf("create AWS config: %w", err)
	}

	accountID, err := helpers.GetAccountId(awsCfg)
	if err != nil {
		return ScanResult{}, fmt.Errorf("get account ID: %w", err)
	}

	cfClient := cloudfront.NewFromConfig(awsCfg)
	s3Client := s3.NewFromConfig(awsCfg)
	r53Client := route53.NewFromConfig(awsCfg)

	slog.InfoContext(ctx, "enumerating CloudFront distributions", "account", accountID)

	distributions, err := enumerateDistributions(ctx, cfClient, accountID)
	if err != nil {
		return ScanResult{}, fmt.Errorf("enumerate distributions: %w", err)
	}
	slog.InfoContext(ctx, "found distributions", "count", len(distributions))

	vulnerable := findVulnerableDistributions(ctx, s3Client, distributions)
	slog.InfoContext(ctx, "found vulnerable distributions", "count", len(vulnerable))

	var risks []output.Risk
	for _, vuln := range vulnerable {
		records, err := findRoute53Records(ctx, r53Client, vuln.DistributionDomain, vuln.Aliases)
		if err != nil {
			slog.WarnContext(ctx, "error searching Route53 records", "distribution", vuln.DistributionID, "error", err)
			records = nil
		}

		risks = append(risks, buildRisk(vuln, records))
	}

	return ScanResult{Risks: risks, AccountID: accountID}, nil
}

func buildRisk(vuln VulnerableDistribution, records []Route53Record) output.Risk {
	status := "TM" // Medium by default
	description := fmt.Sprintf(
		"CloudFront distribution %s points to non-existent S3 bucket '%s'. "+
			"An attacker could create this bucket to serve malicious content.",
		vuln.DistributionID, vuln.MissingBucket,
	)

	// Collect affected domains from Route53 records and aliases
	affectedDomains := collectAffectedDomains(vuln.Aliases, records)

	if len(records) > 0 {
		status = "TH" // High — Route53 records actively point here
		description = fmt.Sprintf(
			"CloudFront distribution %s points to non-existent S3 bucket '%s'. "+
				"Route53 records are actively pointing to this distribution. "+
				"An attacker could create this bucket to serve malicious content on %d domain(s): %s",
			vuln.DistributionID, vuln.MissingBucket,
			len(affectedDomains), strings.Join(affectedDomains, ", "),
		)
	} else if len(affectedDomains) > 0 {
		description = fmt.Sprintf(
			"CloudFront distribution %s points to non-existent S3 bucket '%s'. "+
				"An attacker could create this bucket to serve malicious content on alias domain(s): %s",
			vuln.DistributionID, vuln.MissingBucket,
			strings.Join(affectedDomains, ", "),
		)
	}

	return output.Risk{
		Name:        "cloudfront-s3-takeover",
		DNS:         vuln.DistributionID,
		Status:      status,
		Source:      "aurelian-cloudfront-scanner",
		Description: description,
		Impact: "An attacker could register the missing S3 bucket and serve arbitrary content " +
			"through the CloudFront distribution, enabling subdomain or domain takeover.",
		Recommendation: fmt.Sprintf(
			"1. Delete the CloudFront distribution %s if no longer needed, OR\n"+
				"2. Create the S3 bucket '%s' in your account to reclaim ownership, OR\n"+
				"3. Update the distribution to point to a different, existing origin.",
			vuln.DistributionID, vuln.MissingBucket,
		),
		References: "https://labs.detectify.com/writeups/hostile-subdomain-takeover-using-cloudfront/, " +
			"https://www.hackerone.com/application-security/guide-subdomain-takeovers, " +
			"https://github.com/EdOverflow/can-i-take-over-xyz",
	}
}

func collectAffectedDomains(aliases []string, records []Route53Record) []string {
	seen := make(map[string]bool)
	var domains []string

	for _, r := range records {
		if !seen[r.RecordName] {
			seen[r.RecordName] = true
			domains = append(domains, r.RecordName)
		}
	}
	for _, alias := range aliases {
		if !seen[alias] {
			seen[alias] = true
			domains = append(domains, alias)
		}
	}
	return domains
}
