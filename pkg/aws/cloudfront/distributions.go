package cloudfront

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
)

// CloudFrontAPI defines the subset of the CloudFront client used by enumerateDistributions.
type CloudFrontAPI interface {
	ListDistributions(ctx context.Context, params *cloudfront.ListDistributionsInput, optFns ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error)
	GetDistribution(ctx context.Context, params *cloudfront.GetDistributionInput, optFns ...func(*cloudfront.Options)) (*cloudfront.GetDistributionOutput, error)
}

// isS3Domain returns true if the domain name matches known S3 origin patterns.
func isS3Domain(domain string) bool {
	patterns := []string{".s3.amazonaws.com", ".s3-website.", ".s3-website-", ".s3-", ".s3."}
	return slices.ContainsFunc(patterns, func(p string) bool {
		return strings.Contains(domain, p)
	})
}

// bucketNamePatterns are compiled once and matched in order to extract the
// bucket name from an S3 origin domain. The submatch at the given index
// contains the bucket name.
var bucketNamePatterns = []struct {
	re    *regexp.Regexp
	index int
}{
	// Virtual-hosted style
	{regexp.MustCompile(`^([^.]+)\.s3\.amazonaws\.com`), 1},
	{regexp.MustCompile(`^([^.]+)\.s3\.([a-z0-9-]+)\.amazonaws\.com`), 1},
	{regexp.MustCompile(`^([^.]+)\.s3-([a-z0-9-]+)\.amazonaws\.com`), 1},
	{regexp.MustCompile(`^([^.]+)\.s3-website\.([a-z0-9-]+)\.amazonaws\.com`), 1},
	{regexp.MustCompile(`^([^.]+)\.s3-website-([a-z0-9-]+)\.amazonaws\.com`), 1},
	// Path-style
	{regexp.MustCompile(`^s3\.amazonaws\.com/([^/]+)`), 1},
	{regexp.MustCompile(`^s3\.([a-z0-9-]+)\.amazonaws\.com/([^/]+)`), 2},
	{regexp.MustCompile(`^s3-([a-z0-9-]+)\.amazonaws\.com/([^/]+)`), 2},
}

// extractBucketName extracts the S3 bucket name from an origin domain using regex-based matching.
func extractBucketName(originDomain string) string {
	domain := strings.TrimPrefix(originDomain, "https://")
	domain = strings.TrimPrefix(domain, "http://")

	for _, p := range bucketNamePatterns {
		matches := p.re.FindStringSubmatch(domain)
		if len(matches) > p.index {
			return matches[p.index]
		}
	}

	// Fallback heuristic
	if idx := strings.Index(domain, ".s3"); idx > 0 {
		return domain[:idx]
	}
	return ""
}

// enumerateDistributions lists all CloudFront distributions in the account and returns
// detailed information about each, including their S3 and custom origins.
func enumerateDistributions(ctx context.Context, client CloudFrontAPI, accountID string) ([]DistributionInfo, error) {
	var distributions []DistributionInfo

	paginator := cloudfront.NewListDistributionsPaginator(client, &cloudfront.ListDistributionsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list distributions page: %w", err)
		}

		if page.DistributionList == nil {
			continue
		}

		for _, summary := range page.DistributionList.Items {
			if summary.Id == nil {
				continue
			}

			distID := *summary.Id
			slog.Debug("fetching distribution details", "id", distID)

			dist, err := client.GetDistribution(ctx, &cloudfront.GetDistributionInput{
				Id: summary.Id,
			})
			if err != nil {
				return nil, fmt.Errorf("get distribution %s: %w", distID, err)
			}

			info := buildDistributionInfo(dist, accountID)
			distributions = append(distributions, info)
		}
	}

	return distributions, nil
}

// buildDistributionInfo constructs a DistributionInfo from a GetDistribution response.
func buildDistributionInfo(dist *cloudfront.GetDistributionOutput, accountID string) DistributionInfo {
	info := DistributionInfo{
		AccountID: accountID,
	}

	if dist.Distribution == nil {
		return info
	}

	d := dist.Distribution
	if d.Id != nil {
		info.ID = *d.Id
	}
	if d.DomainName != nil {
		info.DomainName = *d.DomainName
	}

	if d.DistributionConfig == nil {
		return info
	}

	cfg := d.DistributionConfig

	// Extract aliases (alternate domain names / CNAMEs)
	if cfg.Aliases != nil {
		for _, alias := range cfg.Aliases.Items {
			info.Aliases = append(info.Aliases, alias)
		}
	}

	// Extract origins
	if cfg.Origins != nil {
		for _, origin := range cfg.Origins.Items {
			info.Origins = append(info.Origins, buildOriginInfo(origin))
		}
	}

	return info
}

// buildOriginInfo converts an AWS SDK Origin to our OriginInfo type.
func buildOriginInfo(origin cftypes.Origin) OriginInfo {
	oi := OriginInfo{}

	if origin.Id != nil {
		oi.ID = *origin.Id
	}
	if origin.DomainName != nil {
		oi.DomainName = *origin.DomainName
	}

	// An origin is S3 if it has an explicit S3OriginConfig or if the domain matches S3 patterns.
	if origin.S3OriginConfig != nil || isS3Domain(oi.DomainName) {
		oi.OriginType = "s3"
	} else {
		oi.OriginType = "custom"
	}

	return oi
}
