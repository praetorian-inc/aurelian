package aws

import (
	"encoding/json"
	"errors"
	"net"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/utils"
)

type IPLookup struct{}

func init() {
	plugin.Register(&IPLookup{})
}

func (m *IPLookup) ID() string {
	return "aws-ip-lookup"
}

func (m *IPLookup) Name() string {
	return "AWS IP Range Lookup"
}

func (m *IPLookup) Description() string {
	return "Searches AWS IP ranges for a specific IP address"
}

func (m *IPLookup) Platform() plugin.Platform {
	return plugin.PlatformAWS
}

func (m *IPLookup) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *IPLookup) OpsecLevel() string {
	return "low"
}

func (m *IPLookup) Authors() []string {
	return []string{"Praetorian"}
}

func (m *IPLookup) References() []string {
	return []string{"https://ip-ranges.amazonaws.com/ip-ranges.json"}
}

func (m *IPLookup) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("ip", "IP address to lookup in AWS ranges"),
	}
}

type IPRanges struct {
	SyncToken  string    `json:"syncToken"`
	CreateDate string    `json:"createDate"`
	Prefixes   []Prefix  `json:"prefixes"`
	Ipv6       []Prefix6 `json:"ipv6_prefixes"`
}

type Prefix struct {
	IPPrefix           string `json:"ip_prefix"`
	Region             string `json:"region"`
	Service            string `json:"service"`
	NetworkBorderGroup string `json:"network_border_group"`
}

type Prefix6 struct {
	Ipv6Prefix         string `json:"ipv6_prefix"`
	Region             string `json:"region"`
	Service            string `json:"service"`
	NetworkBorderGroup string `json:"network_border_group"`
}

func (m *IPLookup) Run(cfg plugin.Config) ([]plugin.Result, error) {
	ip, _ := cfg.Args["ip"].(string)
	if ip == "" {
		return nil, errors.New("ip parameter is required")
	}

	body, err := utils.Cached_httpGet("https://ip-ranges.amazonaws.com/ip-ranges.json")
	if err != nil {
		return nil, err
	}

	var ipRanges IPRanges
	err = json.Unmarshal(body, &ipRanges)
	if err != nil {
		return nil, err
	}

	targetIP := net.ParseIP(ip)
	if targetIP == nil {
		return nil, errors.New("invalid IP address format")
	}

	// Search IPv4 prefixes
	for _, prefix := range ipRanges.Prefixes {
		_, ipNet, err := net.ParseCIDR(prefix.IPPrefix)
		if err != nil {
			continue
		}

		if ipNet.Contains(targetIP) {
			return []plugin.Result{
				{
					Data: map[string]any{
						"ip":             ip,
						"prefix":         prefix.IPPrefix,
						"region":         prefix.Region,
						"service":        prefix.Service,
						"border_group":   prefix.NetworkBorderGroup,
						"found_in_aws":   true,
						"ip_version":     "ipv4",
					},
				},
			}, nil
		}
	}

	// Search IPv6 prefixes if the target is IPv6
	if targetIP.To4() == nil {
		for _, prefix := range ipRanges.Ipv6 {
			_, ipNet, err := net.ParseCIDR(prefix.Ipv6Prefix)
			if err != nil {
				continue
			}

			if ipNet.Contains(targetIP) {
				return []plugin.Result{
					{
						Data: map[string]any{
							"ip":             ip,
							"prefix":         prefix.Ipv6Prefix,
							"region":         prefix.Region,
							"service":        prefix.Service,
							"border_group":   prefix.NetworkBorderGroup,
							"found_in_aws":   true,
							"ip_version":     "ipv6",
						},
					},
				}, nil
			}
		}
	}

	// IP not found in AWS ranges
	return []plugin.Result{
		{
			Data: map[string]any{
				"ip":           ip,
				"found_in_aws": false,
			},
		},
	}, nil
}
