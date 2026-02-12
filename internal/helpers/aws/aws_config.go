package helpers

import (
	"context"
	"fmt"
	"log/slog"
	"path"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type ConfigLoader func(ctx context.Context, optFns ...func(*config.LoadOptions) error) (aws.Config, error)

var defaultConfigLoader ConfigLoader = config.LoadDefaultConfig

type AWSConfigInput struct {
	Region        string
	Profile       string
	ProfileDir    string
	LoadOptionFns []func(*config.LoadOptions) error
}

func NewAWSConfig(input AWSConfigInput) (aws.Config, error) {
	return newAWSConfigWith(defaultConfigLoader, input)
}

// newAWSConfigWith is the internal implementation that accepts a ConfigLoader for testability.
func newAWSConfigWith(loader ConfigLoader, input AWSConfigInput) (aws.Config, error) {
	region := resolveRegion(input.Region)
	options := buildLoadOptions(region, input.Profile, input.ProfileDir)
	options = append(options, input.LoadOptionFns...)

	cfg, err := loader(context.TODO(), options...)
	if err != nil {
		return aws.Config{}, err
	}

	return cfg, nil
}

func resolveRegion(region string) string {
	if region == "" {
		slog.Warn("Calling NewAWSConfig without a region is risky — it defaults to us-east-1, which might not be what you want. Always provide a region explicitly.")
		return "us-east-1"
	}
	return region
}

func buildLoadOptions(region string, profile string, profileDir string) []func(*config.LoadOptions) error {
	options := []func(*config.LoadOptions) error{
		config.WithRegion(region),
		config.WithRetryMode(aws.RetryModeAdaptive),
	}

	if profile != "" {
		options = append(options, config.WithSharedConfigProfile(profile))
	}

	if profileDir != "" {
		configLocation := path.Join(profileDir, "config")
		credLocation := path.Join(profileDir, "credentials")
		options = append(options,
			config.WithSharedConfigFiles([]string{configLocation}),
			config.WithSharedCredentialsFiles([]string{credLocation}))
	}

	return options
}

// STSCallerIdentityAPI abstracts the STS GetCallerIdentity call for testability
type STSCallerIdentityAPI interface {
	GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

// GetAccountId retrieves the AWS account ID from STS using the provided config.
// Returns the account ID string, or an error if unable to determine account ID.
func GetAccountId(cfg aws.Config) (string, error) {
	client := sts.NewFromConfig(cfg)
	return getAccountIdWith(client)
}

// getAccountIdWith is the internal implementation that accepts an STS client for testability.
func getAccountIdWith(client STSCallerIdentityAPI) (string, error) {
	result, err := client.GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("failed to get caller identity: %w", err)
	}

	if result.Account == nil {
		return "", fmt.Errorf("account ID not found in caller identity")
	}

	return *result.Account, nil
}
