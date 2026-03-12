package cloudfront

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockS3Client implements S3API for testing bucket existence checks.
type mockS3Client struct {
	// bucketResponses maps bucket name to the error returned by HeadBucket.
	// nil means the bucket exists; a non-nil error is returned as-is.
	bucketResponses map[string]error
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
	return &s3.GetBucketLocationOutput{}, nil
}

func TestChecker_Check_MissingBucket(t *testing.T) {
	s3Mock := &mockS3Client{
		bucketResponses: map[string]error{
			"missing-bucket": fmt.Errorf("404 Not Found"),
		},
	}
	r53Mock := &mockRoute53Client{}

	checker := &Checker{s3Client: s3Mock, r53Client: r53Mock}

	dist := DistributionInfo{
		ID:         "EDIST123",
		DomainName: "d123.cloudfront.net",
		AccountID:  "123456789012",
		Aliases:    []string{"www.example.com"},
		Origins: []OriginInfo{
			{
				ID:         "S3-origin",
				DomainName: "missing-bucket.s3.amazonaws.com",
				OriginType: "s3",
			},
		},
	}

	out := pipeline.New[Finding]()
	go func() {
		defer out.Close()
		require.NoError(t, checker.Check(dist, out))
	}()

	findings, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "EDIST123", f.DistributionID)
	assert.Equal(t, "d123.cloudfront.net", f.DistributionDomain)
	assert.Equal(t, "missing-bucket", f.MissingBucket)
	assert.Equal(t, "missing-bucket.s3.amazonaws.com", f.OriginDomain)
	assert.Equal(t, "S3-origin", f.OriginID)
	assert.Equal(t, []string{"www.example.com"}, f.Aliases)
}

func TestChecker_Check_ExistingBucket(t *testing.T) {
	s3Mock := &mockS3Client{
		bucketResponses: map[string]error{
			"healthy-bucket": nil,
		},
	}
	r53Mock := &mockRoute53Client{}

	checker := &Checker{s3Client: s3Mock, r53Client: r53Mock}

	dist := DistributionInfo{
		ID:         "EDIST_HEALTHY",
		DomainName: "d456.cloudfront.net",
		AccountID:  "123456789012",
		Origins: []OriginInfo{
			{
				ID:         "S3-healthy",
				DomainName: "healthy-bucket.s3.amazonaws.com",
				OriginType: "s3",
			},
		},
	}

	out := pipeline.New[Finding]()
	go func() {
		defer out.Close()
		require.NoError(t, checker.Check(dist, out))
	}()

	findings, err := out.Collect()
	require.NoError(t, err)
	assert.Empty(t, findings, "existing bucket should not produce a finding")
}

func TestChecker_Check_CustomOriginSkipped(t *testing.T) {
	s3Mock := &mockS3Client{}
	r53Mock := &mockRoute53Client{}

	checker := &Checker{s3Client: s3Mock, r53Client: r53Mock}

	dist := DistributionInfo{
		ID:         "EDIST_CUSTOM",
		DomainName: "d789.cloudfront.net",
		AccountID:  "123456789012",
		Origins: []OriginInfo{
			{
				ID:         "ALB-origin",
				DomainName: "myalb.us-east-1.elb.amazonaws.com",
				OriginType: "custom",
			},
		},
	}

	out := pipeline.New[Finding]()
	go func() {
		defer out.Close()
		require.NoError(t, checker.Check(dist, out))
	}()

	findings, err := out.Collect()
	require.NoError(t, err)
	assert.Empty(t, findings, "custom origins should not produce findings")
}

func TestChecker_Check_NoRoute53Zones(t *testing.T) {
	s3Mock := &mockS3Client{
		bucketResponses: map[string]error{
			"orphaned-bucket": fmt.Errorf("404 Not Found"),
		},
	}
	r53Mock := &mockRoute53Client{}

	checker := &Checker{s3Client: s3Mock, r53Client: r53Mock}

	dist := DistributionInfo{
		ID:         "EDIST_NOZONES",
		DomainName: "d-nozones.cloudfront.net",
		AccountID:  "123456789012",
		Origins: []OriginInfo{
			{
				ID:         "S3-orphaned",
				DomainName: "orphaned-bucket.s3.amazonaws.com",
				OriginType: "s3",
			},
		},
	}

	out := pipeline.New[Finding]()
	go func() {
		defer out.Close()
		require.NoError(t, checker.Check(dist, out))
	}()

	findings, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, findings, 1, "finding should be emitted even without Route53 zones")

	assert.Equal(t, "EDIST_NOZONES", findings[0].DistributionID)
	assert.Equal(t, "orphaned-bucket", findings[0].MissingBucket)
	assert.Empty(t, findings[0].Route53Records, "no Route53 zones means no records")
}

func TestChecker_Check_WithRoute53Records(t *testing.T) {
	s3Mock := &mockS3Client{
		bucketResponses: map[string]error{
			"vuln-bucket": fmt.Errorf("404 Not Found"),
		},
	}
	r53Mock := &mockRoute53Client{
		hostedZones: []route53types.HostedZone{
			{Id: strPtr("/hostedzone/Z1"), Name: strPtr("example.com.")},
		},
		recordSets: map[string][]route53types.ResourceRecordSet{
			"Z1": {
				{
					Name: strPtr("app.example.com."),
					Type: route53types.RRTypeA,
					AliasTarget: &route53types.AliasTarget{
						DNSName: strPtr("d-vuln.cloudfront.net."),
					},
				},
			},
		},
	}

	checker := &Checker{s3Client: s3Mock, r53Client: r53Mock}

	dist := DistributionInfo{
		ID:         "EDIST_VULN",
		DomainName: "d-vuln.cloudfront.net",
		AccountID:  "123456789012",
		Aliases:    []string{"app.example.com"},
		Origins: []OriginInfo{
			{
				ID:         "S3-vuln",
				DomainName: "vuln-bucket.s3.amazonaws.com",
				OriginType: "s3",
			},
		},
	}

	out := pipeline.New[Finding]()
	go func() {
		defer out.Close()
		require.NoError(t, checker.Check(dist, out))
	}()

	findings, err := out.Collect()
	require.NoError(t, err)
	require.Len(t, findings, 1)

	f := findings[0]
	assert.Equal(t, "EDIST_VULN", f.DistributionID)
	assert.Equal(t, "vuln-bucket", f.MissingBucket)
	require.Len(t, f.Route53Records, 1)
	assert.Equal(t, "app.example.com", f.Route53Records[0].RecordName)
}

func TestChecker_Check_MultipleMissingBuckets(t *testing.T) {
	s3Mock := &mockS3Client{
		bucketResponses: map[string]error{
			"bucket-a": fmt.Errorf("404 Not Found"),
			"bucket-b": fmt.Errorf("404 Not Found"),
		},
	}
	r53Mock := &mockRoute53Client{}

	checker := &Checker{s3Client: s3Mock, r53Client: r53Mock}

	dist := DistributionInfo{
		ID:         "EDIST_MULTI",
		DomainName: "d-multi.cloudfront.net",
		AccountID:  "123456789012",
		Origins: []OriginInfo{
			{ID: "origin-a", DomainName: "bucket-a.s3.amazonaws.com", OriginType: "s3"},
			{ID: "origin-b", DomainName: "bucket-b.s3.amazonaws.com", OriginType: "s3"},
		},
	}

	out := pipeline.New[Finding]()
	go func() {
		defer out.Close()
		require.NoError(t, checker.Check(dist, out))
	}()

	findings, err := out.Collect()
	require.NoError(t, err)
	assert.Len(t, findings, 2, "each missing S3 origin should produce a separate finding")

	buckets := []string{findings[0].MissingBucket, findings[1].MissingBucket}
	assert.Contains(t, buckets, "bucket-a")
	assert.Contains(t, buckets, "bucket-b")
}
