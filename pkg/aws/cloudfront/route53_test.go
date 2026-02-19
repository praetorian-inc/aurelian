package cloudfront

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRoute53Client implements Route53API for testing.
type mockRoute53Client struct {
	hostedZones    []route53types.HostedZone
	recordSets     map[string][]route53types.ResourceRecordSet
	listZonesErr   error
	listRecordsErr error
}

func (m *mockRoute53Client) ListHostedZones(ctx context.Context, params *route53.ListHostedZonesInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error) {
	if m.listZonesErr != nil {
		return nil, m.listZonesErr
	}
	return &route53.ListHostedZonesOutput{
		HostedZones: m.hostedZones,
	}, nil
}

func (m *mockRoute53Client) ListResourceRecordSets(ctx context.Context, params *route53.ListResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	if m.listRecordsErr != nil {
		return nil, m.listRecordsErr
	}
	zoneID := ""
	if params.HostedZoneId != nil {
		zoneID = *params.HostedZoneId
	}
	return &route53.ListResourceRecordSetsOutput{
		ResourceRecordSets: m.recordSets[zoneID],
	}, nil
}

func strPtr(s string) *string { return &s }

func TestFindRoute53Records_AliasMatch(t *testing.T) {
	zoneID := "/hostedzone/Z123"
	zoneName := "example.com."
	cfDomain := "abc123.cloudfront.net"

	client := &mockRoute53Client{
		hostedZones: []route53types.HostedZone{
			{Id: &zoneID, Name: &zoneName},
		},
		recordSets: map[string][]route53types.ResourceRecordSet{
			"Z123": {
				{
					Name: strPtr("www.example.com."),
					Type: route53types.RRTypeA,
					AliasTarget: &route53types.AliasTarget{
						DNSName: strPtr(cfDomain + "."),
					},
				},
			},
		},
	}

	records, err := findRoute53Records(context.Background(), client, cfDomain, nil)
	require.NoError(t, err)
	require.Len(t, records, 1)

	assert.Equal(t, "Z123", records[0].ZoneID)
	assert.Equal(t, "example.com", records[0].ZoneName)
	assert.Equal(t, "www.example.com", records[0].RecordName)
	assert.Equal(t, "A", records[0].RecordType)
	assert.Equal(t, cfDomain, records[0].Value)
}

func TestFindRoute53Records_CNAMEMatchesCloudfrontDomain(t *testing.T) {
	zoneID := "/hostedzone/Z456"
	zoneName := "example.org."
	cfDomain := "xyz.cloudfront.net"

	client := &mockRoute53Client{
		hostedZones: []route53types.HostedZone{
			{Id: &zoneID, Name: &zoneName},
		},
		recordSets: map[string][]route53types.ResourceRecordSet{
			"Z456": {
				{
					Name: strPtr("sub.example.org."),
					Type: route53types.RRTypeCname,
					ResourceRecords: []route53types.ResourceRecord{
						{Value: strPtr(cfDomain + ".")},
					},
				},
			},
		},
	}

	records, err := findRoute53Records(context.Background(), client, cfDomain, nil)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, "CNAME", records[0].RecordType)
	assert.Equal(t, cfDomain, records[0].Value)
}

func TestFindRoute53Records_CNAMEMatchesAlias(t *testing.T) {
	zoneID := "/hostedzone/Z789"
	zoneName := "example.net."
	alias := "custom.alias.example.com"

	client := &mockRoute53Client{
		hostedZones: []route53types.HostedZone{
			{Id: &zoneID, Name: &zoneName},
		},
		recordSets: map[string][]route53types.ResourceRecordSet{
			"Z789": {
				{
					Name: strPtr("site.example.net."),
					Type: route53types.RRTypeCname,
					ResourceRecords: []route53types.ResourceRecord{
						{Value: strPtr(alias)},
					},
				},
			},
		},
	}

	records, err := findRoute53Records(context.Background(), client, "different.cloudfront.net", []string{alias})
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, alias, records[0].Value)
}

func TestFindRoute53Records_NoMatch(t *testing.T) {
	zoneID := "/hostedzone/ZNOMATCH"
	zoneName := "example.io."

	client := &mockRoute53Client{
		hostedZones: []route53types.HostedZone{
			{Id: &zoneID, Name: &zoneName},
		},
		recordSets: map[string][]route53types.ResourceRecordSet{
			"ZNOMATCH": {
				{
					Name: strPtr("other.example.io."),
					Type: route53types.RRTypeCname,
					ResourceRecords: []route53types.ResourceRecord{
						{Value: strPtr("other.target.com")},
					},
				},
			},
		},
	}

	records, err := findRoute53Records(context.Background(), client, "abc.cloudfront.net", nil)
	require.NoError(t, err)
	assert.Empty(t, records)
}

func TestFindRoute53Records_TrailingDotNormalization(t *testing.T) {
	zoneID := "/hostedzone/ZDOTS"
	zoneName := "dots.com."
	cfDomain := "dots.cloudfront.net"

	client := &mockRoute53Client{
		hostedZones: []route53types.HostedZone{
			{Id: &zoneID, Name: &zoneName},
		},
		recordSets: map[string][]route53types.ResourceRecordSet{
			"ZDOTS": {
				{
					Name: strPtr("www.dots.com."),
					Type: route53types.RRTypeA,
					AliasTarget: &route53types.AliasTarget{
						DNSName: strPtr(cfDomain + "."),
					},
				},
			},
		},
	}

	// Pass cloudfrontDomain with trailing dot - should still match
	records, err := findRoute53Records(context.Background(), client, cfDomain+".", nil)
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, cfDomain, records[0].Value)
}

func TestFindRoute53Records_SkipsNilZoneFields(t *testing.T) {
	validZoneID := "/hostedzone/ZVALID"
	validZoneName := "valid.com."
	cfDomain := "valid.cloudfront.net"

	client := &mockRoute53Client{
		hostedZones: []route53types.HostedZone{
			// Zone with nil Id - should be skipped
			{Id: nil, Name: &validZoneName},
			// Zone with nil Name - should be skipped
			{Id: &validZoneID, Name: nil},
			// Valid zone
			{Id: &validZoneID, Name: &validZoneName},
		},
		recordSets: map[string][]route53types.ResourceRecordSet{
			"ZVALID": {
				{
					Name: strPtr("host.valid.com."),
					Type: route53types.RRTypeA,
					AliasTarget: &route53types.AliasTarget{
						DNSName: strPtr(cfDomain),
					},
				},
			},
		},
	}

	records, err := findRoute53Records(context.Background(), client, cfDomain, nil)
	require.NoError(t, err)
	require.Len(t, records, 1)
}
