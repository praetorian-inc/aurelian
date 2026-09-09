package dnstakeover

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockS3Client copies cloudfront.checker_test.go's unexported mock (YAGNI: no shared mock package).
type mockS3Client struct {
	bucketResponses   map[string]error
	locationResponses map[string]error
}

func (m *mockS3Client) HeadBucket(_ context.Context, params *s3.HeadBucketInput, _ ...func(*s3.Options)) (*s3.HeadBucketOutput, error) {
	if params.Bucket == nil {
		return nil, fmt.Errorf("nil bucket name")
	}
	if err, ok := m.bucketResponses[*params.Bucket]; ok {
		if err != nil {
			return nil, err
		}
		return &s3.HeadBucketOutput{}, nil
	}
	return nil, fmt.Errorf("404 Not Found")
}

func (m *mockS3Client) GetBucketLocation(_ context.Context, params *s3.GetBucketLocationInput, _ ...func(*s3.Options)) (*s3.GetBucketLocationOutput, error) {
	if params.Bucket == nil {
		return nil, fmt.Errorf("nil bucket name")
	}
	if m.locationResponses != nil {
		if err, ok := m.locationResponses[*params.Bucket]; ok {
			if err != nil {
				return nil, err
			}
			return &s3.GetBucketLocationOutput{}, nil
		}
	}
	return &s3.GetBucketLocationOutput{}, nil
}

func TestS3BucketFromTarget_VirtualHostedWebsite(t *testing.T) {
	b, ok := s3BucketFromRecord(Route53Record{
		Type:       "CNAME",
		RecordName: "blog.example.com",
		Values:     []string{"mybucket.s3-website-us-east-1.amazonaws.com"},
	})
	require.True(t, ok)
	assert.Equal(t, "mybucket", b)
}

func TestS3BucketFromTarget_AliasEndpointUsesRecordName(t *testing.T) {
	b, ok := s3BucketFromRecord(Route53Record{
		Type:       "A",
		IsAlias:    true,
		RecordName: "shop.example.com",
		Values:     []string{"s3-website-us-east-2.amazonaws.com"},
	})
	require.True(t, ok)
	assert.Equal(t, "shop.example.com", b)
}

func TestS3BucketFromTarget_SkipELB(t *testing.T) {
	_, ok := s3BucketFromRecord(Route53Record{
		Type:    "A",
		IsAlias: true,
		Values:  []string{"dualstack.my-elb.us-east-1.elb.amazonaws.com"},
	})
	assert.False(t, ok)
}

func TestCheckS3_MissingBucketEmitsRisk(t *testing.T) {
	client := &mockS3Client{
		bucketResponses: map[string]error{
			"mybucket": fmt.Errorf("404 Not Found"),
		},
	}
	rec := Route53Record{
		ZoneID:     "Z1",
		ZoneName:   "example.com",
		Type:       "CNAME",
		RecordName: "blog.example.com",
		Values:     []string{"mybucket.s3-website-us-east-1.amazonaws.com"},
	}
	risks := collectS3Risks(t, client, rec)
	require.Len(t, risks, 1)
	assert.Equal(t, "s3-website-subdomain-takeover", risks[0].Name)
	assert.Equal(t, output.RiskSeverityHigh, risks[0].Severity)

	var ctx map[string]any
	require.NoError(t, json.Unmarshal(risks[0].Context, &ctx))
	assert.Equal(t, "mybucket", ctx["bucket_name"])
	assert.Equal(t, "S3 website", ctx["service"])
}

func TestCheckS3_ExistingBucketNoRisk(t *testing.T) {
	client := &mockS3Client{
		bucketResponses: map[string]error{
			"mybucket": nil,
		},
	}
	rec := Route53Record{
		Type:       "CNAME",
		RecordName: "blog.example.com",
		Values:     []string{"mybucket.s3-website-us-east-1.amazonaws.com"},
	}
	assert.Empty(t, collectS3Risks(t, client, rec), "existing bucket must not produce a finding")
}

func TestCheckS3_NotOwnedNoRisk(t *testing.T) {
	client := &mockS3Client{
		bucketResponses: map[string]error{
			"mybucket": fmt.Errorf("PermanentRedirect: bucket is in a different region"),
		},
		locationResponses: map[string]error{
			"mybucket": fmt.Errorf("AccessDenied: access denied"),
		},
	}
	rec := Route53Record{
		Type:       "CNAME",
		RecordName: "blog.example.com",
		Values:     []string{"mybucket.s3-website-us-east-1.amazonaws.com"},
	}
	assert.Empty(t, collectS3Risks(t, client, rec), "BucketExistsNotOwned must not produce an S3-website finding")
}

func collectS3Risks(t *testing.T, client *mockS3Client, rec Route53Record) []output.AurelianRisk {
	t.Helper()
	out := pipeline.New[model.AurelianModel]()
	go func() {
		defer out.Close()
		require.NoError(t, checkS3WithClient(CheckContext{
			Ctx:       context.Background(),
			AccountID: "123456789012",
		}, client, rec, out))
	}()
	items, err := out.Collect()
	require.NoError(t, err)

	risks := make([]output.AurelianRisk, 0, len(items))
	for _, item := range items {
		risk, ok := item.(output.AurelianRisk)
		require.True(t, ok, "expected AurelianRisk, got %T", item)
		risks = append(risks, risk)
	}
	return risks
}
