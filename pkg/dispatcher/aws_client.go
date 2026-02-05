package dispatcher

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

// GetAWSConfig loads AWS configuration for a specific region and profile.
// This helper function is used by all processor functions to obtain AWS SDK clients.
//
// Parameters:
//   - ctx: context for cancellation
//   - region: AWS region (e.g., "us-east-1")
//   - profile: AWS profile name (optional, uses default if empty)
//
// Returns AWS config ready for creating service clients (EC2, Lambda, CloudWatch, etc.)
func GetAWSConfig(ctx context.Context, region, profile string) (aws.Config, error) {
	var opts []func(*config.LoadOptions) error

	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}

	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}

	return config.LoadDefaultConfig(ctx, opts...)
}

// GetAWSConfigFromOptions is a convenience wrapper that extracts region and profile
// from ProcessOptions and calls GetAWSConfig.
func GetAWSConfigFromOptions(ctx context.Context, region string, opts *ProcessOptions) (aws.Config, error) {
	profile := ""
	if opts != nil {
		profile = opts.AWSProfile
	}
	return GetAWSConfig(ctx, region, profile)
}
