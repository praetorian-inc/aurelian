package analyze

import (
	"net"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
)

func TestGCPIPLookupModule_Metadata(t *testing.T) {
	m := &GCPIPLookupModule{}
	assert.Equal(t, "ip-lookup", m.ID())
	assert.Equal(t, "GCP IP Lookup", m.Name())
	assert.Equal(t, plugin.PlatformGCP, m.Platform())
	assert.Equal(t, plugin.CategoryAnalyze, m.Category())
	assert.Equal(t, "safe", m.OpsecLevel())
	assert.NotNil(t, m.Parameters())
}

func TestFindIPInGCPRanges_Match(t *testing.T) {
	ranges := &gcpIPRanges{
		Prefixes: []struct {
			IPv4Prefix string `json:"ipv4Prefix,omitempty"`
			IPv6Prefix string `json:"ipv6Prefix,omitempty"`
			Service    string `json:"service"`
			Scope      string `json:"scope"`
		}{
			{IPv4Prefix: "34.80.0.0/15", Service: "Google Cloud", Scope: "asia-east1"},
		},
	}
	match, found := findIPInGCPRanges(net.ParseIP("34.80.1.1"), ranges)
	assert.True(t, found)
	assert.Equal(t, "34.80.0.0/15", match.IPPrefix)
	assert.Equal(t, "Google Cloud", match.Service)
	assert.Equal(t, "asia-east1", match.Scope)
}

func TestFindIPInGCPRanges_NoMatch(t *testing.T) {
	ranges := &gcpIPRanges{
		Prefixes: []struct {
			IPv4Prefix string `json:"ipv4Prefix,omitempty"`
			IPv6Prefix string `json:"ipv6Prefix,omitempty"`
			Service    string `json:"service"`
			Scope      string `json:"scope"`
		}{
			{IPv4Prefix: "34.80.0.0/15", Service: "Google Cloud", Scope: "asia-east1"},
		},
	}
	_, found := findIPInGCPRanges(net.ParseIP("192.168.1.1"), ranges)
	assert.False(t, found)
}
