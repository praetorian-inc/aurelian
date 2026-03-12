package cloudfront

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLister_List_ARN(t *testing.T) {
	distID := "EDFDVBD632BHDS5"
	client := &mockCloudFrontClient{
		distributions: map[string]*cloudfront.GetDistributionOutput{
			distID: {
				Distribution: &cftypes.Distribution{
					Id:         aws.String(distID),
					DomainName: aws.String("d111.cloudfront.net"),
					DistributionConfig: &cftypes.DistributionConfig{
						Aliases: &cftypes.Aliases{
							Items: []string{"www.example.com"},
						},
						Origins: &cftypes.Origins{
							Items: []cftypes.Origin{
								{
									Id:             aws.String("S3-origin"),
									DomainName:     aws.String("mybucket.s3.amazonaws.com"),
									S3OriginConfig: &cftypes.S3OriginConfig{},
								},
							},
						},
					},
				},
			},
		},
	}

	lister := &Lister{cfClient: client, accountID: "123456789012"}

	arn := "arn:aws:cloudfront::123456789012:distribution/" + distID

	out := pipeline.New[DistributionInfo]()
	go func() {
		defer out.Close()
		require.NoError(t, lister.List(arn, out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, items, 1)

	assert.Equal(t, distID, items[0].ID)
	assert.Equal(t, "d111.cloudfront.net", items[0].DomainName)
	assert.Equal(t, "123456789012", items[0].AccountID)
	assert.Equal(t, []string{"www.example.com"}, items[0].Aliases)
	require.Len(t, items[0].Origins, 1)
	assert.Equal(t, "s3", items[0].Origins[0].OriginType)
	assert.Equal(t, 1, client.getCallCount, "should call GetDistribution exactly once")
}

func TestLister_List_ResourceType(t *testing.T) {
	client := &mockCloudFrontClient{
		listPages: []*cloudfront.ListDistributionsOutput{
			{
				DistributionList: &cftypes.DistributionList{
					IsTruncated: aws.Bool(false),
					Items: []cftypes.DistributionSummary{
						{Id: aws.String("DIST1"), DomainName: aws.String("d1.cloudfront.net")},
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

	lister := &Lister{cfClient: client, accountID: "123456789012"}

	out := pipeline.New[DistributionInfo]()
	go func() {
		defer out.Close()
		require.NoError(t, lister.List("AWS::CloudFront::Distribution", out))
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	assert.Len(t, items, 2)
	assert.Equal(t, "DIST1", items[0].ID)
	assert.Equal(t, "DIST2", items[1].ID)
}

func TestLister_List_InvalidIdentifier(t *testing.T) {
	lister := &Lister{cfClient: &mockCloudFrontClient{}, accountID: "123456789012"}

	out := pipeline.New[DistributionInfo]()
	go func() {
		defer out.Close()
		err := lister.List("not-an-arn-or-type", out)
		assert.ErrorContains(t, err, "identifier must be an ARN or CloudControl resource type")
	}()

	items, err := out.Collect()
	require.NoError(t, err)
	assert.Empty(t, items)
}

func TestParseDistributionID(t *testing.T) {
	tests := []struct {
		name     string
		resource string
		wantID   string
		wantErr  bool
	}{
		{
			name:     "valid distribution resource",
			resource: "distribution/EDFDVBD632BHDS5",
			wantID:   "EDFDVBD632BHDS5",
		},
		{
			name:     "wrong prefix",
			resource: "origin-access-identity/cloudfront/E127EXAMPLE51Z",
			wantErr:  true,
		},
		{
			name:     "empty resource",
			resource: "",
			wantErr:  true,
		},
		{
			name:     "distribution prefix with empty ID",
			resource: "distribution/",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := parseDistributionID(tt.resource)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantID, id)
		})
	}
}
