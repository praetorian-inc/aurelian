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
	assert.Equal(t, "blog.example.com", b)
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

func TestS3BucketFromTarget_SkipNonAWS_S3Substring(t *testing.T) {
	_, ok := s3BucketFromRecord(Route53Record{
		Type:       "CNAME",
		RecordName: "files.example.com",
		Values:     []string{"files.s3.internal.example.com"},
	})
	assert.False(t, ok, "non-AWS host containing .s3 must not parse as an S3 website bucket")
}

func TestS3BucketFromTarget_SkipAccessPointObjectLambdaVPCE(t *testing.T) {
	tests := []struct {
		name string
		host string
	}{
		{"s3-accesspoint", "myap-123456789012.s3-accesspoint.us-east-1.amazonaws.com"},
		{"s3-object-lambda", "mylambda-123456789012.s3-object-lambda.us-east-1.amazonaws.com"},
		{"s3-vpce", "bucket.vpce-0123456789abcdef0-abcdefgh.s3.us-east-1.vpce.amazonaws.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ok := s3BucketFromRecord(Route53Record{
				Type:       "CNAME",
				RecordName: "files.example.com",
				Values:     []string{tt.host},
			})
			assert.False(t, ok)
		})
	}
}

func TestS3BucketFromTarget_WebsiteBucketLabelContainsAccessPoint(t *testing.T) {
	b, ok := s3BucketFromRecord(Route53Record{
		Type:       "CNAME",
		RecordName: "blog.example.com",
		Values:     []string{"logs-s3-accesspoint.s3-website-us-east-1.amazonaws.com"},
	})
	require.True(t, ok)
	assert.Equal(t, "blog.example.com", b)
}

func TestCheckS3_MissingBucketEmitsRisk(t *testing.T) {
	client := &mockS3Client{
		bucketResponses: map[string]error{
			"blog.example.com": fmt.Errorf("404 Not Found"),
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
	assert.Equal(t, "blog.example.com", ctx["bucket_name"])
	assert.Equal(t, "S3 website", ctx["service"])
}

func TestCheckS3_ExistingBucketNoRisk(t *testing.T) {
	client := &mockS3Client{
		bucketResponses: map[string]error{
			"blog.example.com": nil,
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
			"blog.example.com": fmt.Errorf("PermanentRedirect: bucket is in a different region"),
		},
		locationResponses: map[string]error{
			"blog.example.com": fmt.Errorf("AccessDenied: access denied"),
		},
	}
	rec := Route53Record{
		Type:       "CNAME",
		RecordName: "blog.example.com",
		Values:     []string{"mybucket.s3-website-us-east-1.amazonaws.com"},
	}
	assert.Empty(t, collectS3Risks(t, client, rec), "BucketExistsNotOwned must not produce an S3-website finding")
}

func TestCheckS3_TargetLabelMissingRecordBucketPresentNoRisk(t *testing.T) {
	client := &mockS3Client{
		bucketResponses: map[string]error{
			"mybucket":         fmt.Errorf("404 Not Found"),
			"blog.example.com": nil,
		},
	}
	rec := Route53Record{
		Type:       "CNAME",
		RecordName: "blog.example.com",
		Values:     []string{"mybucket.s3-website-us-east-1.amazonaws.com"},
	}
	assert.Empty(t, collectS3Risks(t, client, rec), "missing CNAME target label must not produce a finding when the record-hostname bucket exists")
}

func TestCheckS3_RecordBucketMissingTargetLabelPresentEmitsRisk(t *testing.T) {
	client := &mockS3Client{
		bucketResponses: map[string]error{
			"blog.example.com": fmt.Errorf("404 Not Found"),
			"mybucket":         nil,
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

	var ctx map[string]any
	require.NoError(t, json.Unmarshal(risks[0].Context, &ctx))
	assert.Equal(t, "blog.example.com", ctx["bucket_name"])
}

func collectS3Risks(t *testing.T, client *mockS3Client, rec Route53Record) []output.AurelianRisk {
	t.Helper()
	out := pipeline.New[model.AurelianModel]()
	errCh := make(chan error, 1)
	go func() {
		defer out.Close()
		errCh <- checkS3WithClient(CheckContext{
			Ctx:       context.Background(),
			AccountID: "123456789012",
		}, client, rec, out)
	}()
	items, err := out.Collect()
	require.NoError(t, err)
	require.NoError(t, <-errCh)

	risks := make([]output.AurelianRisk, 0, len(items))
	for _, item := range items {
		risk, ok := item.(output.AurelianRisk)
		require.True(t, ok, "expected AurelianRisk, got %T", item)
		risks = append(risks, risk)
	}
	return risks
}
