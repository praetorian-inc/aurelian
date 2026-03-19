package analyze

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testIPRanges() *awsIPRanges {
	return &awsIPRanges{
		Prefixes: []struct {
			IPPrefix           string `json:"ip_prefix"`
			Region             string `json:"region"`
			Service            string `json:"service"`
			NetworkBorderGroup string `json:"network_border_group"`
		}{
			{
				IPPrefix:           "3.5.140.0/22",
				Region:             "ap-northeast-2",
				Service:            "AMAZON",
				NetworkBorderGroup: "ap-northeast-2",
			},
			{
				IPPrefix:           "52.94.0.0/22",
				Region:             "us-east-1",
				Service:            "S3",
				NetworkBorderGroup: "us-east-1",
			},
		},
		IPv6Prefixes: []struct {
			IPv6Prefix         string `json:"ipv6_prefix"`
			Region             string `json:"region"`
			Service            string `json:"service"`
			NetworkBorderGroup string `json:"network_border_group"`
		}{
			{
				IPv6Prefix:         "2600:1f01:4874::/48",
				Region:             "us-east-1",
				Service:            "EC2",
				NetworkBorderGroup: "us-east-1",
			},
		},
	}
}

func TestFindIPInRanges_IPv4Match(t *testing.T) {
	ranges := testIPRanges()
	ip := net.ParseIP("3.5.140.5")
	require.NotNil(t, ip)

	match, found := findIPInRanges(ip, ranges)

	assert.True(t, found)
	assert.Equal(t, "3.5.140.0/22", match.IPPrefix)
	assert.Equal(t, "ap-northeast-2", match.Region)
	assert.Equal(t, "AMAZON", match.Service)
	assert.Equal(t, "ap-northeast-2", match.NetworkBorderGroup)
	assert.Empty(t, match.IPv6Prefix)
}

func TestFindIPInRanges_IPv4NoMatch(t *testing.T) {
	ranges := testIPRanges()
	ip := net.ParseIP("1.2.3.4")
	require.NotNil(t, ip)

	_, found := findIPInRanges(ip, ranges)

	assert.False(t, found)
}

func TestFindIPInRanges_IPv6Match(t *testing.T) {
	ranges := testIPRanges()
	ip := net.ParseIP("2600:1f01:4874::1")
	require.NotNil(t, ip)

	match, found := findIPInRanges(ip, ranges)

	assert.True(t, found)
	assert.Equal(t, "2600:1f01:4874::/48", match.IPv6Prefix)
	assert.Equal(t, "us-east-1", match.Region)
	assert.Equal(t, "EC2", match.Service)
	assert.Equal(t, "us-east-1", match.NetworkBorderGroup)
	assert.Empty(t, match.IPPrefix)
}

func TestFindIPInRanges_IPv6NoMatch(t *testing.T) {
	ranges := testIPRanges()
	ip := net.ParseIP("2001:db8::1")
	require.NotNil(t, ip)

	_, found := findIPInRanges(ip, ranges)

	assert.False(t, found)
}

func TestFindIPInRanges_EmptyRanges(t *testing.T) {
	ranges := &awsIPRanges{}
	ip := net.ParseIP("52.94.0.1")
	require.NotNil(t, ip)

	_, found := findIPInRanges(ip, ranges)

	assert.False(t, found)
}

func TestFindIPInRanges_IPv4MatchReturnsCorrectService(t *testing.T) {
	ranges := testIPRanges()
	// 52.94.0.1 is in the S3 range
	ip := net.ParseIP("52.94.0.1")
	require.NotNil(t, ip)

	match, found := findIPInRanges(ip, ranges)

	assert.True(t, found)
	assert.Equal(t, "S3", match.Service)
	assert.Equal(t, "us-east-1", match.Region)
}
