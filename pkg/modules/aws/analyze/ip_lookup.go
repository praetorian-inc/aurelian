package analyze

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/utils"
)

var httpClient = &utils.CachedHTTPClient{}

const awsIPRangesURL = "https://ip-ranges.amazonaws.com/ip-ranges.json"

func init() {
	plugin.Register(&IPLookupModule{})
}

type IPLookupConfig struct {
	IP string `param:"ip" desc:"IP address to look up in AWS IP ranges" required:"true"`
}

type IPLookupModule struct {
	IPLookupConfig
}

func (m *IPLookupModule) ID() string                { return "ip-lookup" }
func (m *IPLookupModule) Name() string              { return "AWS IP Lookup" }
func (m *IPLookupModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *IPLookupModule) Category() plugin.Category { return plugin.CategoryAnalyze }
func (m *IPLookupModule) OpsecLevel() string        { return "safe" }
func (m *IPLookupModule) Authors() []string         { return []string{"Praetorian"} }

func (m *IPLookupModule) Description() string {
	return "Looks up an IP address against the AWS published IP ranges to determine whether it belongs to AWS, " +
		"and if so, which service, region, and network border group."
}

func (m *IPLookupModule) References() []string {
	return []string{
		"https://ip-ranges.amazonaws.com/ip-ranges.json",
	}
}

func (m *IPLookupModule) SupportedResourceTypes() []string {
	return nil
}

func (m *IPLookupModule) Parameters() any {
	return &m.IPLookupConfig
}

// ipRangeMatch holds the matched prefix data returned to the caller.
type ipRangeMatch struct {
	IPPrefix           string `json:"ip_prefix,omitempty"`
	IPv6Prefix         string `json:"ipv6_prefix,omitempty"`
	Region             string `json:"region"`
	Service            string `json:"service"`
	NetworkBorderGroup string `json:"network_border_group"`
}

func (m *IPLookupModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.IPLookupConfig

	ip := net.ParseIP(c.IP)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", c.IP)
	}

	cfg.Info("fetching AWS IP ranges")

	ranges, err := fetchAWSIPRanges()
	if err != nil {
		return fmt.Errorf("fetching AWS IP ranges: %w", err)
	}

	match, found := findIPInRanges(ip, ranges)

	var resultsJSON []byte
	if found {
		cfg.Info("found match: %s (%s, %s)", match.IPPrefix+match.IPv6Prefix, match.Service, match.Region)
		resultsJSON, err = json.Marshal(match)
	} else {
		cfg.Info("IP %s not found in AWS ranges", c.IP)
		resultsJSON, err = json.Marshal(map[string]string{"result": "not found"})
	}

	if err != nil {
		return fmt.Errorf("marshaling results: %w", err)
	}

	out.Send(output.AnalyzeResult{
		Module:  m.ID(),
		Input:   c.IP,
		Results: json.RawMessage(resultsJSON),
	})

	return nil
}

// awsIPRanges is the structure of the AWS ip-ranges.json file.
type awsIPRanges struct {
	Prefixes []struct {
		IPPrefix           string `json:"ip_prefix"`
		Region             string `json:"region"`
		Service            string `json:"service"`
		NetworkBorderGroup string `json:"network_border_group"`
	} `json:"prefixes"`
	IPv6Prefixes []struct {
		IPv6Prefix         string `json:"ipv6_prefix"`
		Region             string `json:"region"`
		Service            string `json:"service"`
		NetworkBorderGroup string `json:"network_border_group"`
	} `json:"ipv6_prefixes"`
}

func fetchAWSIPRanges() (*awsIPRanges, error) {
	body, err := httpClient.Get(awsIPRangesURL)
	if err != nil {
		return nil, err
	}
	var ranges awsIPRanges
	if err := json.Unmarshal(body, &ranges); err != nil {
		return nil, fmt.Errorf("parsing IP ranges JSON: %w", err)
	}
	return &ranges, nil
}

func findIPInRanges(ip net.IP, ranges *awsIPRanges) (ipRangeMatch, bool) {
	for _, prefix := range ranges.Prefixes {
		_, network, err := net.ParseCIDR(prefix.IPPrefix)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return ipRangeMatch{
				IPPrefix:           prefix.IPPrefix,
				Region:             prefix.Region,
				Service:            prefix.Service,
				NetworkBorderGroup: prefix.NetworkBorderGroup,
			}, true
		}
	}

	for _, prefix := range ranges.IPv6Prefixes {
		_, network, err := net.ParseCIDR(prefix.IPv6Prefix)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return ipRangeMatch{
				IPv6Prefix:         prefix.IPv6Prefix,
				Region:             prefix.Region,
				Service:            prefix.Service,
				NetworkBorderGroup: prefix.NetworkBorderGroup,
			}, true
		}
	}

	return ipRangeMatch{}, false
}
