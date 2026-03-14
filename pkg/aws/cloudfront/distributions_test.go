package cloudfront

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockCloudFrontClient implements CloudFrontAPI for testing.
type mockCloudFrontClient struct {
	listPages     []*cloudfront.ListDistributionsOutput
	distributions map[string]*cloudfront.GetDistributionOutput
	listCallCount int
	getCallCount  int
}

func (m *mockCloudFrontClient) ListDistributions(_ context.Context, params *cloudfront.ListDistributionsInput, _ ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error) {
	if m.listCallCount >= len(m.listPages) {
		return &cloudfront.ListDistributionsOutput{
			DistributionList: &cftypes.DistributionList{Items: nil},
		}, nil
	}
	page := m.listPages[m.listCallCount]
	m.listCallCount++
	return page, nil
}

func (m *mockCloudFrontClient) GetDistribution(_ context.Context, params *cloudfront.GetDistributionInput, _ ...func(*cloudfront.Options)) (*cloudfront.GetDistributionOutput, error) {
	m.getCallCount++
	if params.Id == nil {
		return &cloudfront.GetDistributionOutput{}, nil
	}
	dist, ok := m.distributions[*params.Id]
	if !ok {
		return &cloudfront.GetDistributionOutput{}, nil
	}
	return dist, nil
}

func TestIsS3Domain(t *testing.T) {
	tests := []struct {
		domain   string
		expected bool
	}{
		{"mybucket.s3.amazonaws.com", true},
		{"mybucket.s3.us-east-1.amazonaws.com", true},
		{"mybucket.s3-us-east-1.amazonaws.com", true},
		{"mybucket.s3-website.us-east-1.amazonaws.com", true},
		{"mybucket.s3-website-us-east-1.amazonaws.com", true},
		// path-style base host without bucket prefix does not match
		{"s3.amazonaws.com", false},
		{"api.example.com", false},
		{"alb.us-east-1.elb.amazonaws.com", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			assert.Equal(t, tt.expected, isS3Domain(tt.domain))
		})
	}
}

func TestExtractBucketName(t *testing.T) {
	tests := []struct {
		domain   string
		expected string
	}{
		// Virtual-hosted style
		{"mybucket.s3.amazonaws.com", "mybucket"},
		{"mybucket.s3.us-east-1.amazonaws.com", "mybucket"},
		{"mybucket.s3-us-west-2.amazonaws.com", "mybucket"},
		{"mybucket.s3-website.us-east-1.amazonaws.com", "mybucket"},
		{"mybucket.s3-website-us-east-1.amazonaws.com", "mybucket"},
		// Path-style
		{"s3.amazonaws.com/mybucket", "mybucket"},
		{"s3.us-east-1.amazonaws.com/mybucket", "mybucket"},
		{"s3-us-west-2.amazonaws.com/mybucket", "mybucket"},
		// With scheme prefix
		{"https://mybucket.s3.amazonaws.com", "mybucket"},
		{"http://mybucket.s3.amazonaws.com", "mybucket"},
		// Fallback heuristic
		{"mybucket.s3-custom.example.com", "mybucket"},
		// No match
		{"api.example.com", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractBucketName(tt.domain))
		})
	}
}

func TestEnumerateDistributions_Empty(t *testing.T) {
	client := &mockCloudFrontClient{
		listPages: []*cloudfront.ListDistributionsOutput{
			{
				DistributionList: &cftypes.DistributionList{
					IsTruncated: aws.Bool(false),
					Items:       nil,
				},
			},
		},
		distributions: map[string]*cloudfront.GetDistributionOutput{},
	}

	dists, err := enumerateDistributions(context.Background(), client, "123456789012")
	require.NoError(t, err)
	assert.Empty(t, dists)
}

func TestEnumerateDistributions_S3Origin(t *testing.T) {
	distID := "EDFDVBD632BHDS5"
	client := &mockCloudFrontClient{
		listPages: []*cloudfront.ListDistributionsOutput{
			{
				DistributionList: &cftypes.DistributionList{
					IsTruncated: aws.Bool(false),
					Items: []cftypes.DistributionSummary{
						{
							Id:         aws.String(distID),
							DomainName: aws.String("d111111abcdef8.cloudfront.net"),
						},
					},
				},
			},
		},
		distributions: map[string]*cloudfront.GetDistributionOutput{
			distID: {
				Distribution: &cftypes.Distribution{
					Id:         aws.String(distID),
					DomainName: aws.String("d111111abcdef8.cloudfront.net"),
					DistributionConfig: &cftypes.DistributionConfig{
						Aliases: &cftypes.Aliases{
							Items:    []string{"www.example.com"},
							Quantity: aws.Int32(1),
						},
						Origins: &cftypes.Origins{
							Items: []cftypes.Origin{
								{
									Id:             aws.String("my-s3-origin"),
									DomainName:     aws.String("mybucket.s3.amazonaws.com"),
									S3OriginConfig: &cftypes.S3OriginConfig{},
								},
							},
							Quantity: aws.Int32(1),
						},
					},
				},
			},
		},
	}

	dists, err := enumerateDistributions(context.Background(), client, "123456789012")
	require.NoError(t, err)
	require.Len(t, dists, 1)

	dist := dists[0]
	assert.Equal(t, distID, dist.ID)
	assert.Equal(t, "d111111abcdef8.cloudfront.net", dist.DomainName)
	assert.Equal(t, "123456789012", dist.AccountID)
	assert.Equal(t, []string{"www.example.com"}, dist.Aliases)
	require.Len(t, dist.Origins, 1)
	assert.Equal(t, "my-s3-origin", dist.Origins[0].ID)
	assert.Equal(t, "mybucket.s3.amazonaws.com", dist.Origins[0].DomainName)
	assert.Equal(t, "s3", dist.Origins[0].OriginType)
}

func TestEnumerateDistributions_CustomOrigin(t *testing.T) {
	distID := "EDFDVBD632BHDS6"
	client := &mockCloudFrontClient{
		listPages: []*cloudfront.ListDistributionsOutput{
			{
				DistributionList: &cftypes.DistributionList{
					IsTruncated: aws.Bool(false),
					Items: []cftypes.DistributionSummary{
						{
							Id:         aws.String(distID),
							DomainName: aws.String("d222222abcdef8.cloudfront.net"),
						},
					},
				},
			},
		},
		distributions: map[string]*cloudfront.GetDistributionOutput{
			distID: {
				Distribution: &cftypes.Distribution{
					Id:         aws.String(distID),
					DomainName: aws.String("d222222abcdef8.cloudfront.net"),
					DistributionConfig: &cftypes.DistributionConfig{
						Origins: &cftypes.Origins{
							Items: []cftypes.Origin{
								{
									Id:                 aws.String("my-alb-origin"),
									DomainName:         aws.String("myalb.us-east-1.elb.amazonaws.com"),
									CustomOriginConfig: &cftypes.CustomOriginConfig{},
								},
							},
							Quantity: aws.Int32(1),
						},
					},
				},
			},
		},
	}

	dists, err := enumerateDistributions(context.Background(), client, "123456789012")
	require.NoError(t, err)
	require.Len(t, dists, 1)

	dist := dists[0]
	require.Len(t, dist.Origins, 1)
	assert.Equal(t, "custom", dist.Origins[0].OriginType)
}

func TestEnumerateDistributions_S3DomainWithoutS3OriginConfig(t *testing.T) {
	// S3 static website hosting origins use CustomOriginConfig but have S3 domain
	distID := "EDFDVBD632BHDS7"
	client := &mockCloudFrontClient{
		listPages: []*cloudfront.ListDistributionsOutput{
			{
				DistributionList: &cftypes.DistributionList{
					IsTruncated: aws.Bool(false),
					Items: []cftypes.DistributionSummary{
						{
							Id:         aws.String(distID),
							DomainName: aws.String("d333333abcdef8.cloudfront.net"),
						},
					},
				},
			},
		},
		distributions: map[string]*cloudfront.GetDistributionOutput{
			distID: {
				Distribution: &cftypes.Distribution{
					Id:         aws.String(distID),
					DomainName: aws.String("d333333abcdef8.cloudfront.net"),
					DistributionConfig: &cftypes.DistributionConfig{
						Origins: &cftypes.Origins{
							Items: []cftypes.Origin{
								{
									Id:                 aws.String("my-s3-website"),
									DomainName:         aws.String("mybucket.s3-website-us-east-1.amazonaws.com"),
									CustomOriginConfig: &cftypes.CustomOriginConfig{},
									// S3OriginConfig is nil for static website hosted buckets
								},
							},
							Quantity: aws.Int32(1),
						},
					},
				},
			},
		},
	}

	dists, err := enumerateDistributions(context.Background(), client, "123456789012")
	require.NoError(t, err)
	require.Len(t, dists, 1)

	// Domain pattern should cause this to be detected as s3 even without S3OriginConfig
	assert.Equal(t, "s3", dists[0].Origins[0].OriginType)
}

func TestEnumerateDistributions_Pagination(t *testing.T) {
	marker := "NEXTMARKER"
	client := &mockCloudFrontClient{
		listPages: []*cloudfront.ListDistributionsOutput{
			{
				DistributionList: &cftypes.DistributionList{
					IsTruncated: aws.Bool(true),
					NextMarker:  aws.String(marker),
					Items: []cftypes.DistributionSummary{
						{Id: aws.String("DIST1"), DomainName: aws.String("d1.cloudfront.net")},
					},
				},
			},
			{
				DistributionList: &cftypes.DistributionList{
					IsTruncated: aws.Bool(false),
					Items: []cftypes.DistributionSummary{
						{Id: aws.String("DIST2"), DomainName: aws.String("d2.cloudfront.net")},
					},
				},
			},
		},
		distributions: map[string]*cloudfront.GetDistributionOutput{
			"DIST1": {
				Distribution: &cftypes.Distribution{
					Id:                 aws.String("DIST1"),
					DomainName:         aws.String("d1.cloudfront.net"),
					DistributionConfig: &cftypes.DistributionConfig{},
				},
			},
			"DIST2": {
				Distribution: &cftypes.Distribution{
					Id:                 aws.String("DIST2"),
					DomainName:         aws.String("d2.cloudfront.net"),
					DistributionConfig: &cftypes.DistributionConfig{},
				},
			},
		},
	}

	dists, err := enumerateDistributions(context.Background(), client, "123456789012")
	require.NoError(t, err)
	assert.Len(t, dists, 2)
	assert.Equal(t, "DIST1", dists[0].ID)
	assert.Equal(t, "DIST2", dists[1].ID)
}
