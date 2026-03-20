package helpers

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/account"
	awstypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
)

// Mock implementations for testability

type mockAccountClient struct {
	listRegionsFunc func(ctx context.Context, params *account.ListRegionsInput, optFns ...func(*account.Options)) (*account.ListRegionsOutput, error)
}

func (m *mockAccountClient) ListRegions(ctx context.Context, params *account.ListRegionsInput, optFns ...func(*account.Options)) (*account.ListRegionsOutput, error) {
	if m.listRegionsFunc != nil {
		return m.listRegionsFunc(ctx, params, optFns...)
	}
	return nil, fmt.Errorf("not implemented")
}

type mockEC2Client struct {
	describeRegionsFunc func(ctx context.Context, params *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
}

func (m *mockEC2Client) DescribeRegions(ctx context.Context, params *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	if m.describeRegionsFunc != nil {
		return m.describeRegionsFunc(ctx, params, optFns...)
	}
	return nil, fmt.Errorf("not implemented")
}

func TestEnabledRegions_AccountAPISuccess(t *testing.T) {
	// Setup mock Account API that returns regions
	mockAccount := &mockAccountClient{
		listRegionsFunc: func(ctx context.Context, params *account.ListRegionsInput, optFns ...func(*account.Options)) (*account.ListRegionsOutput, error) {
			usEast1 := "us-east-1"
			usWest2 := "us-west-2"
			return &account.ListRegionsOutput{
				Regions: []awstypes.Region{
					{RegionName: &usEast1},
					{RegionName: &usWest2},
				},
			}, nil
		},
	}

	resolver := &RegionResolver{
		accountClient: mockAccount,
	}

	regions, err := resolver.GetEnabledRegions(context.Background())

	assert.NoError(t, err)
	assert.Equal(t, []string{"us-east-1", "us-west-2"}, regions)
}

func TestEnabledRegions_AccountAPIFails_FallsBackToEC2(t *testing.T) {
	// Account API fails
	mockAccount := &mockAccountClient{
		listRegionsFunc: func(ctx context.Context, params *account.ListRegionsInput, optFns ...func(*account.Options)) (*account.ListRegionsOutput, error) {
			return nil, fmt.Errorf("account API error")
		},
	}

	// EC2 API succeeds
	mockEC2 := &mockEC2Client{
		describeRegionsFunc: func(ctx context.Context, params *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
			usEast1 := "us-east-1"
			euWest1 := "eu-west-1"
			return &ec2.DescribeRegionsOutput{
				Regions: []ec2types.Region{
					{RegionName: &usEast1},
					{RegionName: &euWest1},
				},
			}, nil
		},
	}

	resolver := &RegionResolver{
		accountClient: mockAccount,
		ec2Client:     mockEC2,
	}

	regions, err := resolver.GetEnabledRegions(context.Background())

	assert.NoError(t, err)
	assert.Equal(t, []string{"us-east-1", "eu-west-1"}, regions)
}

func TestEnabledRegions_BothAPIsFail_FallsBackToHardcoded(t *testing.T) {
	// Account API fails
	mockAccount := &mockAccountClient{
		listRegionsFunc: func(ctx context.Context, params *account.ListRegionsInput, optFns ...func(*account.Options)) (*account.ListRegionsOutput, error) {
			return nil, fmt.Errorf("account API error")
		},
	}

	// EC2 API fails
	mockEC2 := &mockEC2Client{
		describeRegionsFunc: func(ctx context.Context, params *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
			return nil, fmt.Errorf("ec2 API error")
		},
	}

	resolver := &RegionResolver{
		accountClient: mockAccount,
		ec2Client:     mockEC2,
	}

	regions, err := resolver.GetEnabledRegions(context.Background())

	assert.NoError(t, err)
	// Should fallback to hardcoded Regions list
	assert.Equal(t, Regions, regions)
	assert.Greater(t, len(regions), 0, "hardcoded Regions list should not be empty")
}

func TestEnabledRegions_FullTieredFallback(t *testing.T) {
	tests := []struct {
		name              string
		accountError      error
		accountRegions    []string
		ec2Error          error
		ec2Regions        []string
		expectedRegions   []string
		expectedFallback  string
	}{
		{
			name:             "Account API success",
			accountError:     nil,
			accountRegions:   []string{"us-east-1", "us-west-2"},
			expectedRegions:  []string{"us-east-1", "us-west-2"},
			expectedFallback: "account",
		},
		{
			name:             "Account fails, EC2 succeeds",
			accountError:     fmt.Errorf("account error"),
			ec2Error:         nil,
			ec2Regions:       []string{"us-east-1", "eu-west-1"},
			expectedRegions:  []string{"us-east-1", "eu-west-1"},
			expectedFallback: "ec2",
		},
		{
			name:             "Both fail, hardcoded fallback",
			accountError:     fmt.Errorf("account error"),
			ec2Error:         fmt.Errorf("ec2 error"),
			expectedRegions:  Regions,
			expectedFallback: "hardcoded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockAccount := &mockAccountClient{
				listRegionsFunc: func(ctx context.Context, params *account.ListRegionsInput, optFns ...func(*account.Options)) (*account.ListRegionsOutput, error) {
					if tt.accountError != nil {
						return nil, tt.accountError
					}
					var regions []awstypes.Region
					for _, r := range tt.accountRegions {
						rCopy := r
						regions = append(regions, awstypes.Region{RegionName: &rCopy})
					}
					return &account.ListRegionsOutput{Regions: regions}, nil
				},
			}

			mockEC2 := &mockEC2Client{
				describeRegionsFunc: func(ctx context.Context, params *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
					if tt.ec2Error != nil {
						return nil, tt.ec2Error
					}
					var regions []ec2types.Region
					for _, r := range tt.ec2Regions {
						rCopy := r
						regions = append(regions, ec2types.Region{RegionName: &rCopy})
					}
					return &ec2.DescribeRegionsOutput{Regions: regions}, nil
				},
			}

			resolver := &RegionResolver{
				accountClient: mockAccount,
				ec2Client:     mockEC2,
			}

			regions, err := resolver.GetEnabledRegions(context.Background())

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedRegions, regions)
		})
	}
}

func TestEnabledRegions_EmptyProfile(t *testing.T) {
	// Test that EnabledRegions works with empty profile
	mockAccount := &mockAccountClient{
		listRegionsFunc: func(ctx context.Context, params *account.ListRegionsInput, optFns ...func(*account.Options)) (*account.ListRegionsOutput, error) {
			usEast1 := "us-east-1"
			return &account.ListRegionsOutput{
				Regions: []awstypes.Region{
					{RegionName: &usEast1},
				},
			}, nil
		},
	}

	resolver := &RegionResolver{
		accountClient: mockAccount,
	}

	regions, err := resolver.GetEnabledRegions(context.Background())

	assert.NoError(t, err)
	assert.Equal(t, []string{"us-east-1"}, regions)
}

func TestEnabledRegions_IntegrationWithNewAWSConfig(t *testing.T) {
	// Test that EnabledRegions signature accepts profile and profileDir
	// This will be the public API
	profile := "test-profile"
	profileDir := "/tmp/test-profiles"

	// Create a mock config
	mockCfg := aws.Config{
		Region: "us-east-1",
	}

	// Mock the config loader
	oldLoader := defaultConfigLoader
	defer func() { defaultConfigLoader = oldLoader }()

	defaultConfigLoader = func(ctx context.Context, optFns ...func(*config.LoadOptions) error) (aws.Config, error) {
		return mockCfg, nil
	}

	// This should compile and work with the new signature
	regions, err := EnabledRegions(profile, profileDir)

	// We expect it to fallback to hardcoded list since we don't have real AWS clients
	assert.NoError(t, err)
	assert.NotEmpty(t, regions)
}
