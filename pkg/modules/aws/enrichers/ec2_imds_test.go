package enrichers_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	smithy "github.com/aws/smithy-go"
	"github.com/praetorian-inc/aurelian/pkg/modules/aws/enrichers"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockIMDSClient struct {
	output *ec2.DescribeInstancesOutput
	err    error
}

func (m *mockIMDSClient) DescribeInstances(ctx context.Context, input *ec2.DescribeInstancesInput, opts ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return m.output, m.err
}

func TestFetchIMDSMetadata(t *testing.T) {
	cfg := plugin.EnricherConfig{
		Context:   context.Background(),
		AWSConfig: aws.Config{},
	}

	t.Run("IMDSv1 allowed", func(t *testing.T) {
		client := &mockIMDSClient{
			output: &ec2.DescribeInstancesOutput{
				Reservations: []ec2types.Reservation{{
					Instances: []ec2types.Instance{{
						State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
						MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{
							HttpTokens:              ec2types.HttpTokensStateOptional,
							HttpEndpoint:            ec2types.InstanceMetadataEndpointStateEnabled,
							HttpPutResponseHopLimit: aws.Int32(1),
						},
					}},
				}},
			},
		}

		r := &output.AWSResource{
			ResourceType: "AWS::EC2::Instance",
			ResourceID:   "i-0123456789abcdef0",
			Properties:   make(map[string]any),
		}

		err := enrichers.FetchIMDSMetadata(cfg, r, client)
		require.NoError(t, err)
		assert.Equal(t, "optional", r.Properties["MetadataHttpTokens"])
		assert.Equal(t, "enabled", r.Properties["MetadataHttpEndpoint"])
		assert.Equal(t, 1, r.Properties["MetadataHttpPutResponseHopLimit"])
		assert.Equal(t, "running", r.Properties["InstanceStateName"])
	})

	t.Run("IMDSv2 enforced", func(t *testing.T) {
		client := &mockIMDSClient{
			output: &ec2.DescribeInstancesOutput{
				Reservations: []ec2types.Reservation{{
					Instances: []ec2types.Instance{{
						State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
						MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{
							HttpTokens:              ec2types.HttpTokensStateRequired,
							HttpEndpoint:            ec2types.InstanceMetadataEndpointStateEnabled,
							HttpPutResponseHopLimit: aws.Int32(2),
						},
					}},
				}},
			},
		}

		r := &output.AWSResource{
			ResourceType: "AWS::EC2::Instance",
			ResourceID:   "i-0123456789abcdef0",
			Properties:   make(map[string]any),
		}

		err := enrichers.FetchIMDSMetadata(cfg, r, client)
		require.NoError(t, err)
		assert.Equal(t, "required", r.Properties["MetadataHttpTokens"])
		assert.Equal(t, "enabled", r.Properties["MetadataHttpEndpoint"])
	})

	t.Run("IMDS disabled", func(t *testing.T) {
		client := &mockIMDSClient{
			output: &ec2.DescribeInstancesOutput{
				Reservations: []ec2types.Reservation{{
					Instances: []ec2types.Instance{{
						State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
						MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{
							HttpTokens:              ec2types.HttpTokensStateOptional,
							HttpEndpoint:            ec2types.InstanceMetadataEndpointStateDisabled,
							HttpPutResponseHopLimit: aws.Int32(1),
						},
					}},
				}},
			},
		}

		r := &output.AWSResource{
			ResourceType: "AWS::EC2::Instance",
			ResourceID:   "i-0123456789abcdef0",
			Properties:   make(map[string]any),
		}

		err := enrichers.FetchIMDSMetadata(cfg, r, client)
		require.NoError(t, err)
		assert.Equal(t, "disabled", r.Properties["MetadataHttpEndpoint"])
	})

	t.Run("nil MetadataOptions uses defaults", func(t *testing.T) {
		client := &mockIMDSClient{
			output: &ec2.DescribeInstancesOutput{
				Reservations: []ec2types.Reservation{{
					Instances: []ec2types.Instance{{
						State:           &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
						MetadataOptions: nil,
					}},
				}},
			},
		}

		r := &output.AWSResource{
			ResourceType: "AWS::EC2::Instance",
			ResourceID:   "i-0123456789abcdef0",
			Properties:   make(map[string]any),
		}

		err := enrichers.FetchIMDSMetadata(cfg, r, client)
		require.NoError(t, err)
		assert.Equal(t, "optional", r.Properties["MetadataHttpTokens"])
		assert.Equal(t, "enabled", r.Properties["MetadataHttpEndpoint"])
		assert.Equal(t, "running", r.Properties["InstanceStateName"])
	})

	t.Run("terminated instance", func(t *testing.T) {
		client := &mockIMDSClient{
			output: &ec2.DescribeInstancesOutput{
				Reservations: []ec2types.Reservation{{
					Instances: []ec2types.Instance{{
						State: &ec2types.InstanceState{Name: ec2types.InstanceStateNameTerminated},
						MetadataOptions: &ec2types.InstanceMetadataOptionsResponse{
							HttpTokens:              ec2types.HttpTokensStateOptional,
							HttpEndpoint:            ec2types.InstanceMetadataEndpointStateEnabled,
							HttpPutResponseHopLimit: aws.Int32(1),
						},
					}},
				}},
			},
		}

		r := &output.AWSResource{
			ResourceType: "AWS::EC2::Instance",
			ResourceID:   "i-0123456789abcdef0",
			Properties:   make(map[string]any),
		}

		err := enrichers.FetchIMDSMetadata(cfg, r, client)
		require.NoError(t, err)
		assert.Equal(t, "terminated", r.Properties["InstanceStateName"])
	})

	t.Run("instance not found", func(t *testing.T) {
		client := &mockIMDSClient{
			err: &smithy.GenericAPIError{
				Code:    "InvalidInstanceID.NotFound",
				Message: "The instance ID 'i-nonexistent' does not exist",
			},
		}

		r := &output.AWSResource{
			ResourceType: "AWS::EC2::Instance",
			ResourceID:   "i-nonexistent",
			Properties:   make(map[string]any),
		}

		err := enrichers.FetchIMDSMetadata(cfg, r, client)
		assert.NoError(t, err)
		assert.Empty(t, r.Properties, "No properties should be added for missing instance")
	})
}
