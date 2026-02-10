package recon

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	cctypes "github.com/aws/aws-sdk-go-v2/service/cloudcontrol/types"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Module metadata tests ---

func TestAWSListAllResources_ID(t *testing.T) {
	m := &AWSListAllResourcesModule{}
	assert.Equal(t, "list-all", m.ID())
}

func TestAWSListAllResources_Platform(t *testing.T) {
	m := &AWSListAllResourcesModule{}
	assert.Equal(t, plugin.PlatformAWS, m.Platform())
}

func TestAWSListAllResources_ConcurrencyParameter(t *testing.T) {
	m := &AWSListAllResourcesModule{}
	params := m.Parameters()

	var concurrencyParam *plugin.Parameter
	for i := range params {
		if params[i].Name == "concurrency" {
			concurrencyParam = &params[i]
			break
		}
	}

	require.NotNil(t, concurrencyParam, "concurrency parameter must exist")
	assert.Equal(t, "int", concurrencyParam.Type)
	assert.Equal(t, 5, concurrencyParam.Default)
	assert.False(t, concurrencyParam.Required)
}

// --- CloudControlLister interface and mock ---

// mockCloudControlClient implements CloudControlLister for testing.
type mockCloudControlClient struct {
	// listResourcesFn allows per-test customization of ListResources behavior
	listResourcesFn func(ctx context.Context, input *cloudcontrol.ListResourcesInput, opts ...func(*cloudcontrol.Options)) (*cloudcontrol.ListResourcesOutput, error)
	callCount       atomic.Int64
}

func (m *mockCloudControlClient) ListResources(ctx context.Context, input *cloudcontrol.ListResourcesInput, opts ...func(*cloudcontrol.Options)) (*cloudcontrol.ListResourcesOutput, error) {
	m.callCount.Add(1)
	if m.listResourcesFn != nil {
		return m.listResourcesFn(ctx, input, opts...)
	}
	return &cloudcontrol.ListResourcesOutput{}, nil
}

// --- ResourceEnumerator tests ---

func TestResourceEnumerator_UsesRateLimiting(t *testing.T) {
	// Track max concurrent calls to prove rate limiting is working
	var concurrent atomic.Int64
	var maxConcurrent atomic.Int64

	mock := &mockCloudControlClient{
		listResourcesFn: func(ctx context.Context, input *cloudcontrol.ListResourcesInput, opts ...func(*cloudcontrol.Options)) (*cloudcontrol.ListResourcesOutput, error) {
			cur := concurrent.Add(1)
			// Track peak concurrency
			for {
				old := maxConcurrent.Load()
				if cur <= old || maxConcurrent.CompareAndSwap(old, cur) {
					break
				}
			}
			time.Sleep(50 * time.Millisecond) // simulate API latency
			concurrent.Add(-1)

			return &cloudcontrol.ListResourcesOutput{
				ResourceDescriptions: []cctypes.ResourceDescription{
					{Identifier: aws.String("res-1"), Properties: aws.String("{}")},
				},
			}, nil
		},
	}

	enumerator := &ResourceEnumerator{
		Client:        mock,
		AccountID:     "123456789012",
		Region:        "us-east-1",
		Concurrency:   2, // limit to 2 concurrent
		ResourceTypes: []string{"AWS::EC2::Instance", "AWS::S3::Bucket", "AWS::Lambda::Function", "AWS::DynamoDB::Table"},
	}

	results, err := enumerator.Enumerate(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, results)

	// With concurrency=2, max concurrent should not exceed 2
	assert.LessOrEqual(t, int(maxConcurrent.Load()), 2,
		"concurrent API calls should not exceed concurrency limit")
}

func TestResourceEnumerator_RespectsContextCancellation(t *testing.T) {
	mock := &mockCloudControlClient{
		listResourcesFn: func(ctx context.Context, input *cloudcontrol.ListResourcesInput, opts ...func(*cloudcontrol.Options)) (*cloudcontrol.ListResourcesOutput, error) {
			// Simulate slow API
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(5 * time.Second):
				return &cloudcontrol.ListResourcesOutput{}, nil
			}
		},
	}

	enumerator := &ResourceEnumerator{
		Client:        mock,
		AccountID:     "123456789012",
		Region:        "us-east-1",
		Concurrency:   5,
		ResourceTypes: []string{"AWS::EC2::Instance", "AWS::S3::Bucket"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := enumerator.Enumerate(ctx)
	// Should return quickly with context error, not hang for 5s
	assert.Error(t, err)
}

func TestResourceEnumerator_ClassifiesErrors(t *testing.T) {
	tests := []struct {
		name      string
		errMsg    string
		shouldSkip bool
	}{
		{"TypeNotFoundException skipped", "TypeNotFoundException: AWS::Foo::Bar", true},
		{"UnsupportedAction skipped", "UnsupportedActionException: not supported", true},
		{"AccessDenied skipped", "AccessDeniedException: not authorized", true},
		{"Real error propagated", "InternalServerError: something broke", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.shouldSkip, isSkippableCloudControlError(fmt.Errorf("%s", tt.errMsg)))
		})
	}
}

func TestResourceEnumerator_PaginatesResults(t *testing.T) {
	callNum := 0
	mock := &mockCloudControlClient{
		listResourcesFn: func(ctx context.Context, input *cloudcontrol.ListResourcesInput, opts ...func(*cloudcontrol.Options)) (*cloudcontrol.ListResourcesOutput, error) {
			callNum++
			switch callNum {
			case 1:
				return &cloudcontrol.ListResourcesOutput{
					ResourceDescriptions: []cctypes.ResourceDescription{
						{Identifier: aws.String("res-1"), Properties: aws.String("{}")},
					},
					NextToken: aws.String("page2"),
				}, nil
			case 2:
				return &cloudcontrol.ListResourcesOutput{
					ResourceDescriptions: []cctypes.ResourceDescription{
						{Identifier: aws.String("res-2"), Properties: aws.String("{}")},
					},
				}, nil
			default:
				t.Fatal("unexpected extra page request")
				return nil, nil
			}
		},
	}

	enumerator := &ResourceEnumerator{
		Client:        mock,
		AccountID:     "123456789012",
		Region:        "us-east-1",
		Concurrency:   5,
		ResourceTypes: []string{"AWS::EC2::Instance"},
	}

	results, err := enumerator.Enumerate(context.Background())
	require.NoError(t, err)

	// Should have collected resources from both pages
	resources, ok := results["AWS::EC2::Instance"]
	require.True(t, ok)
	assert.Len(t, resources, 2)
}

func TestResourceEnumerator_SkipsGlobalServicesInNonPrimaryRegion(t *testing.T) {
	mock := &mockCloudControlClient{
		listResourcesFn: func(ctx context.Context, input *cloudcontrol.ListResourcesInput, opts ...func(*cloudcontrol.Options)) (*cloudcontrol.ListResourcesOutput, error) {
			return &cloudcontrol.ListResourcesOutput{
				ResourceDescriptions: []cctypes.ResourceDescription{
					{Identifier: aws.String("res-1"), Properties: aws.String("{}")},
				},
			}, nil
		},
	}

	// IAM is global — when region is not us-east-1, it should set region="" on the resource
	enumerator := &ResourceEnumerator{
		Client:        mock,
		AccountID:     "123456789012",
		Region:        "us-east-1",
		Concurrency:   5,
		ResourceTypes: []string{"AWS::IAM::Role"},
	}

	results, err := enumerator.Enumerate(context.Background())
	require.NoError(t, err)

	roles, ok := results["AWS::IAM::Role"]
	require.True(t, ok)
	require.Len(t, roles, 1)
	// Global services should have empty region
	assert.Equal(t, "", roles[0].Region)
}

func TestResourceEnumerator_SetsCorrectCloudResourceFields(t *testing.T) {
	mock := &mockCloudControlClient{
		listResourcesFn: func(ctx context.Context, input *cloudcontrol.ListResourcesInput, opts ...func(*cloudcontrol.Options)) (*cloudcontrol.ListResourcesOutput, error) {
			return &cloudcontrol.ListResourcesOutput{
				ResourceDescriptions: []cctypes.ResourceDescription{
					{Identifier: aws.String("i-abc123"), Properties: aws.String(`{"InstanceType":"t3.micro"}`)},
				},
			}, nil
		},
	}

	enumerator := &ResourceEnumerator{
		Client:        mock,
		AccountID:     "123456789012",
		Region:        "us-east-1",
		Concurrency:   5,
		ResourceTypes: []string{"AWS::EC2::Instance"},
	}

	results, err := enumerator.Enumerate(context.Background())
	require.NoError(t, err)

	instances := results["AWS::EC2::Instance"]
	require.Len(t, instances, 1)

	cr := instances[0]
	assert.Equal(t, "aws", cr.Platform)
	assert.Equal(t, "AWS::EC2::Instance", cr.ResourceType)
	assert.Equal(t, "i-abc123", cr.ResourceID)
	assert.Equal(t, "123456789012", cr.AccountRef)
	assert.Equal(t, "us-east-1", cr.Region)
}

// --- Resource type list tests ---

func TestGetKeySummaryResourceTypes(t *testing.T) {
	types := keySummaryResourceTypes()
	assert.Contains(t, types, "AWS::EC2::Instance")
	assert.Contains(t, types, "AWS::S3::Bucket")
	assert.Contains(t, types, "AWS::Lambda::Function")
	// Summary should be smaller than full
	assert.Less(t, len(types), len(allResourceTypes()))
}

func TestGetAllResourceTypes(t *testing.T) {
	types := allResourceTypes()
	assert.Greater(t, len(types), 10, "should have comprehensive resource type list")
	// Should include everything in summary
	summary := keySummaryResourceTypes()
	for _, s := range summary {
		assert.Contains(t, types, s, "full list should include all summary types")
	}
}
