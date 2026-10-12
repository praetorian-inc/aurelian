package dnstakeover

import (
	"testing"

	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/stretchr/testify/require"
)

func TestRecordValues_AliasDNSName(t *testing.T) {
	dnsName := "s3-website-us-east-2.amazonaws.com."
	rrs := r53types.ResourceRecordSet{
		Type:        r53types.RRTypeA,
		AliasTarget: &r53types.AliasTarget{DNSName: &dnsName},
	}
	got := recordValues(rrs)
	require.Equal(t, []string{"s3-website-us-east-2.amazonaws.com"}, got)
}

func TestRecordValues_CNAMEResourceRecordsUnchanged(t *testing.T) {
	v := "prefix.us-east-2.elasticbeanstalk.com."
	rrs := r53types.ResourceRecordSet{
		Type:            r53types.RRTypeCname,
		ResourceRecords: []r53types.ResourceRecord{{Value: &v}},
	}
	got := recordValues(rrs)
	require.Equal(t, []string{"prefix.us-east-2.elasticbeanstalk.com."}, got)
}

func TestRecordValues_EmptyRecordSet(t *testing.T) {
	got := recordValues(r53types.ResourceRecordSet{})
	require.Empty(t, got)
}

func TestRecordValues_AliasNilDNSName(t *testing.T) {
	rrs := r53types.ResourceRecordSet{
		Type:        r53types.RRTypeA,
		AliasTarget: &r53types.AliasTarget{DNSName: nil},
	}
	got := recordValues(rrs)
	require.Empty(t, got)
}

func TestRecordValues_ResourceRecordsAndAlias(t *testing.T) {
	rr := "kept.example.com."
	alias := "s3-website-us-east-2.amazonaws.com."
	rrs := r53types.ResourceRecordSet{
		Type:            r53types.RRTypeA,
		ResourceRecords: []r53types.ResourceRecord{{Value: &rr}},
		AliasTarget:     &r53types.AliasTarget{DNSName: &alias},
	}
	got := recordValues(rrs)
	require.Equal(t, []string{"kept.example.com.", "s3-website-us-east-2.amazonaws.com"}, got)
}
