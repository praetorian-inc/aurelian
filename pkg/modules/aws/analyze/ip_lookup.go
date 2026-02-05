package analyze

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/utils"
)

func init() {
	plugin.Register(&IPLookupModule{})
}

// IPLookupModule searches AWS IP ranges for a specific IP address
type IPLookupModule struct{}

func (m *IPLookupModule) ID() string {
	return "ip-lookup"
}

func (m *IPLookupModule) Name() string {
	return "AWS IP Lookup"
}

func (m *IPLookupModule) Description() string {
	return "Search AWS IP ranges for a specific IP address"
}

func (m *IPLookupModule) Platform() plugin.Platform {
	return plugin.PlatformAWS
}

func (m *IPLookupModule) Category() plugin.Category {
	return plugin.CategoryAnalyze
}

func (m *IPLookupModule) OpsecLevel() string {
	return "stealth"
}

func (m *IPLookupModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *IPLookupModule) References() []string {
	return []string{
		"https://ip-ranges.amazonaws.com/ip-ranges.json",
	}
}

func (m *IPLookupModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "ip",
			Description: "IP address to search for in AWS ranges",
			Type:        "string",
			Required:    true,
		},
	}
}

func (m *IPLookupModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Get IP parameter
	ip, ok := cfg.Args["ip"].(string)
	if !ok || ip == "" {
		return nil, fmt.Errorf("ip parameter is required")
	}

	// Download AWS IP ranges (with caching)
	body, err := utils.Cached_httpGet("https://ip-ranges.amazonaws.com/ip-ranges.json")
	if err != nil {
		return nil, fmt.Errorf("error getting AWS IP ranges: %w", err)
	}

	// Parse JSON
	var ipRanges IPRanges
	if err := json.Unmarshal(body, &ipRanges); err != nil {
		return nil, fmt.Errorf("error unmarshalling AWS IP ranges: %w", err)
	}

	// Parse target IP
	targetIP := net.ParseIP(ip)
	if targetIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	// Search IPv4 prefixes
	for _, prefix := range ipRanges.Prefixes {
		_, ipNet, err := net.ParseCIDR(prefix.IPPrefix)
		if err != nil {
			continue // Skip invalid CIDR
		}

		if ipNet.Contains(targetIP) {
			data := map[string]any{
				"status":               "found",
				"ip":                   ip,
				"ip_prefix":            prefix.IPPrefix,
				"region":               prefix.Region,
				"service":              prefix.Service,
				"network_border_group": prefix.NetworkBorderGroup,
				"ip_version":           "ipv4",
			}

			return []plugin.Result{
				{
					Data: data,
					Metadata: map[string]any{
						"module":      "ip-lookup",
						"platform":    "aws",
						"opsec_level": "stealth",
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
				continue // Skip invalid CIDR
			}

			if ipNet.Contains(targetIP) {
				data := map[string]any{
					"status":               "found",
					"ip":                   ip,
					"ip_prefix":            prefix.Ipv6Prefix,
					"region":               prefix.Region,
					"service":              prefix.Service,
					"network_border_group": prefix.NetworkBorderGroup,
					"ip_version":           "ipv6",
				}

				return []plugin.Result{
					{
						Data: data,
						Metadata: map[string]any{
							"module":      "ip-lookup",
							"platform":    "aws",
							"opsec_level": "stealth",
						},
					},
				}, nil
			}
		}
	}

	// IP not found in AWS ranges
	data := map[string]any{
		"status": "not_found",
		"ip":     ip,
	}

	return []plugin.Result{
		{
			Data: data,
			Metadata: map[string]any{
				"module":      "ip-lookup",
				"platform":    "aws",
				"opsec_level": "stealth",
			},
		},
	}, nil
}

// IPRanges represents the AWS IP ranges JSON structure
type IPRanges struct {
	SyncToken  string    `json:"syncToken"`
	CreateDate string    `json:"createDate"`
	Prefixes   []Prefix  `json:"prefixes"`
	Ipv6       []Prefix6 `json:"ipv6_prefixes"`
}

// Prefix represents an IPv4 prefix in AWS IP ranges
type Prefix struct {
	IPPrefix           string `json:"ip_prefix"`
	Region             string `json:"region"`
	Service            string `json:"service"`
	NetworkBorderGroup string `json:"network_border_group"`
}

// Prefix6 represents an IPv6 prefix in AWS IP ranges
type Prefix6 struct {
	Ipv6Prefix         string `json:"ipv6_prefix"`
	Region             string `json:"region"`
	Service            string `json:"service"`
	NetworkBorderGroup string `json:"network_border_group"`
}
