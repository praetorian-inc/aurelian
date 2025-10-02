package cloudfront

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/aws"

	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/helpers"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
)

// CloudFrontDistributionEnumerator enumerates all CloudFront distributions
type CloudFrontDistributionEnumerator struct {
	*base.AwsReconLink
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
	OriginType string `json:"origin_type"` // "s3", "custom", etc.
}

// NewCloudFrontDistributionEnumerator creates a new CloudFront distribution enumerator
func NewCloudFrontDistributionEnumerator(configs ...cfg.Config) chain.Link {
	enumerator := &CloudFrontDistributionEnumerator{}
	enumerator.AwsReconLink = base.NewAwsReconLink(enumerator, configs...)
	return enumerator
}

// Process enumerates CloudFront distributions
func (c *CloudFrontDistributionEnumerator) Process(resource any) error {
	// CloudFront is a global service, always use us-east-1
	region := "us-east-1"

	config, err := c.GetConfigWithRuntimeArgs(region)
	if err != nil {
		return fmt.Errorf("failed to get AWS config: %w", err)
	}

	accountID, err := c.GetAccountID(config)
	if err != nil {
		slog.Warn("Failed to get account ID", "error", err)
		accountID = "unknown"
	}

	client := cloudfront.NewFromConfig(config)

	slog.Info("Enumerating CloudFront distributions")

	paginator := cloudfront.NewListDistributionsPaginator(client, &cloudfront.ListDistributionsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			slog.Error("Failed to list distributions", "error", err)
			return err
		}

		if page.DistributionList == nil || page.DistributionList.Items == nil {
			slog.Debug("No CloudFront distributions found")
			continue
		}

		for _, distSummary := range page.DistributionList.Items {
			if distSummary.Id == nil {
				continue
			}

			// Get detailed distribution config
			distResult, err := client.GetDistribution(context.TODO(), &cloudfront.GetDistributionInput{
				Id: distSummary.Id,
			})
			if err != nil {
				slog.Error("Failed to get distribution details", "id", *distSummary.Id, "error", err)
				continue
			}

			if distResult.Distribution == nil || distResult.Distribution.DistributionConfig == nil {
				continue
			}

			dist := distResult.Distribution
			config := dist.DistributionConfig

			// Build distribution info
			info := CloudFrontDistributionInfo{
				ID:         *distSummary.Id,
				DomainName: *distSummary.DomainName,
				Region:     region,
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

					originInfo := OriginInfo{
						ID:         *origin.Id,
						DomainName: *origin.DomainName,
					}

					// Determine origin type
					if origin.S3OriginConfig != nil {
						originInfo.OriginType = "s3"
					} else if origin.CustomOriginConfig != nil {
						originInfo.OriginType = "custom"
					} else {
						// Check if domain looks like S3
						domainName := *origin.DomainName
						if isS3Domain(domainName) {
							originInfo.OriginType = "s3"
						} else {
							originInfo.OriginType = "custom"
						}
					}

					info.Origins = append(info.Origins, originInfo)
				}
			}

			slog.Info("Found CloudFront distribution",
				"id", info.ID,
				"domain", info.DomainName,
				"aliases", len(info.Aliases),
				"origins", len(info.Origins))

			// Send distribution info to next link
			if err := c.Send(info); err != nil {
				return err
			}
		}
	}

	return nil
}

// GetAccountID retrieves the AWS account ID
func (c *CloudFrontDistributionEnumerator) GetAccountID(config aws.Config) (string, error) {
	return helpers.GetAccountId(config)
}

// isS3Domain checks if a domain looks like an S3 domain
func isS3Domain(domain string) bool {
	// Check for various S3 domain patterns
	patterns := []string{
		".s3.amazonaws.com",
		".s3-",
		".s3.",
	}

	for _, pattern := range patterns {
		if contains(domain, pattern) {
			return true
		}
	}

	return false
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
