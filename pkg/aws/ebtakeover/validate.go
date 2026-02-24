package ebtakeover

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// ebAPI is the subset of the Elastic Beanstalk client used by this package.
type ebAPI interface {
	CheckDNSAvailability(ctx context.Context, params *elasticbeanstalk.CheckDNSAvailabilityInput, optFns ...func(*elasticbeanstalk.Options)) (*elasticbeanstalk.CheckDNSAvailabilityOutput, error)
}

// ValidateCandidates checks each candidate against the Elastic Beanstalk
// CheckDNSAvailability API. Candidates where Available=true are dangling.
// Candidates are grouped by region to reuse API clients efficiently.
func ValidateCandidates(candidates []EBCandidate, opts ScanOptions) ([]DanglingRecord, error) {
	// Group candidates by EB region.
	byRegion := make(map[string][]EBCandidate)
	for _, c := range candidates {
		byRegion[c.EBRegion] = append(byRegion[c.EBRegion], c)
	}

	limiter := ratelimit.NewAWSRegionLimiter(opts.Concurrency)

	var dangling []DanglingRecord
	resultCh := make(chan DanglingRecord, len(candidates))
	errCh := make(chan error, len(byRegion))

	// Process each region concurrently, respecting the rate limiter.
	for region, regionCandidates := range byRegion {
		region := region
		regionCandidates := regionCandidates

		go func() {
			release, err := limiter.Acquire(context.Background(), region)
			if err != nil {
				errCh <- fmt.Errorf("acquire limiter for %s: %w", region, err)
				return
			}
			defer release()

			cfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
				Region:     region,
				Profile:    opts.Profile,
				ProfileDir: opts.ProfileDir,
			})
			if err != nil {
				errCh <- fmt.Errorf("create eb config for region %s: %w", region, err)
				return
			}

			client := elasticbeanstalk.NewFromConfig(cfg)
			for _, c := range regionCandidates {
				available, err := checkDNSAvailability(client, c.EBPrefix)
				if err != nil {
					errCh <- fmt.Errorf("check dns availability for %s in %s: %w", c.EBPrefix, region, err)
					return
				}
				if available {
					resultCh <- DanglingRecord{
						ZoneID:       c.ZoneID,
						ZoneName:     c.ZoneName,
						RecordName:   c.RecordName,
						CNAMETarget:  c.CNAMETarget,
						EBRegion:     c.EBRegion,
						EBPrefix:     c.EBPrefix,
						DNSAvailable: true,
					}
				}
			}
			errCh <- nil
		}()
	}

	// Collect results from all regions.
	for range byRegion {
		if err := <-errCh; err != nil {
			return nil, err
		}
	}
	close(resultCh)

	for r := range resultCh {
		dangling = append(dangling, r)
	}

	return dangling, nil
}

// checkDNSAvailability returns true when the given EB prefix is unclaimed
// (i.e., the CNAME is available to register — meaning the record is dangling).
func checkDNSAvailability(client ebAPI, prefix string) (bool, error) {
	out, err := client.CheckDNSAvailability(context.Background(), &elasticbeanstalk.CheckDNSAvailabilityInput{
		CNAMEPrefix: aws.String(prefix),
	})
	if err != nil {
		return false, err
	}
	if out.Available == nil {
		return false, nil
	}
	return *out.Available, nil
}
