package cloudfront

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	helpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
)

// Scan detects CloudFront distributions with S3 origins pointing to non-existent
// buckets. It enumerates distributions, checks bucket existence, queries Route53
// for pointing records, and returns findings.
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

	var findings []Finding
	for _, vuln := range vulnerable {
		records, err := findRoute53Records(ctx, r53Client, vuln.DistributionDomain, vuln.Aliases)
		if err != nil {
			slog.WarnContext(ctx, "error searching Route53 records", "distribution", vuln.DistributionID, "error", err)
			records = nil
		}

		findings = append(findings, Finding{
			VulnerableDistribution: vuln,
			Route53Records:         records,
		})
	}

	return ScanResult{Findings: findings, AccountID: accountID}, nil
}
