package eiptakeover

import (
	"fmt"
	"log/slog"

	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
)

// Scan runs the full EIP dangling A record detection pipeline and returns
// a slice of output.Risk findings for any dangling records discovered.
func Scan(opts ScanOptions) ([]output.Risk, error) {
	// Step 1: Resolve account ID via STS
	cfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
		Region:     "us-east-1",
		Profile:    opts.Profile,
		ProfileDir: opts.ProfileDir,
	})
	if err != nil {
		return nil, fmt.Errorf("create aws config: %w", err)
	}

	accountID, err := awshelpers.GetAccountId(cfg)
	if err != nil {
		return nil, fmt.Errorf("resolve account id: %w", err)
	}
	opts.AccountID = accountID
	slog.Info("eip-takeover: resolved account", "account_id", accountID)

	// Step 2: Enumerate Route53 A records
	slog.Info("eip-takeover: enumerating route53 a records")
	aRecords, err := FindARecords(opts.Profile, opts.ProfileDir)
	if err != nil {
		return nil, fmt.Errorf("find a records: %w", err)
	}
	slog.Info("eip-takeover: found a records", "count", len(aRecords))

	// Step 3: Fetch AWS IP ranges
	slog.Info("eip-takeover: fetching aws ip ranges")
	awsRanges, err := FetchAWSIPRanges()
	if err != nil {
		return nil, fmt.Errorf("fetch aws ip ranges: %w", err)
	}
	slog.Info("eip-takeover: loaded aws ip prefixes", "count", len(awsRanges.prefixes))

	// Step 4: Enumerate allocated Elastic IPs across all regions
	slog.Info("eip-takeover: enumerating allocated elastic ips", "regions", len(opts.Regions))
	allocatedEIPs, err := FetchAllocatedEIPs(opts)
	if err != nil {
		return nil, fmt.Errorf("fetch allocated eips: %w", err)
	}
	slog.Info("eip-takeover: found allocated eips", "count", len(allocatedEIPs))

	// Step 5: Identify dangling records
	var risks []output.Risk
	for _, rec := range aRecords {
		for _, ip := range rec.IPs {
			awsRegion, awsService, inAWS := awsRanges.Contains(ip)
			if !inAWS {
				continue
			}
			if allocatedEIPs[ip] {
				continue
			}

			dangling := DanglingARecord{
				ZoneID:     rec.ZoneID,
				ZoneName:   rec.ZoneName,
				RecordName: rec.RecordName,
				IP:         ip,
				AWSService: awsService,
				AWSRegion:  awsRegion,
			}
			slog.Info("eip-takeover: dangling record found",
				"record", rec.RecordName,
				"zone", rec.ZoneName,
				"ip", ip,
				"aws_region", awsRegion,
				"aws_service", awsService,
			)
			risks = append(risks, dangling.ToRisk(accountID))
		}
	}

	slog.Info("eip-takeover: scan complete", "dangling_count", len(risks))
	return risks, nil
}
