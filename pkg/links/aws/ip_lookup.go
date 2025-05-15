package aws

import (
	"encoding/json"
	"net"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

type IPLookup struct {
	*chain.Base
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

func NewIPLookup(configs ...cfg.Config) chain.Link {
	l := &IPLookup{}
	l.Base = chain.NewBase(l, configs...)
	l.SetDescription("Searches AWS IP ranges for a specific IP address")
	return l
}

func (l *IPLookup) Process(ip string) error {
	l.Logger.Info("Downloading AWS IP ranges")
	body, err := utils.Cached_httpGet("https://ip-ranges.amazonaws.com/ip-ranges.json")
	if err != nil {
		l.Logger.Error("Error getting AWS IP ranges", "error", err)
		return err
	}

	var ipRanges IPRanges
	err = json.Unmarshal(body, &ipRanges)
	if err != nil {
		l.Logger.Error("Error unmarshalling AWS IP ranges", "error", err)
		return err
	}

	l.Logger.Info("Searching for IP in AWS ranges", "ip", ip)
	targetIP := net.ParseIP(ip)
	if targetIP == nil {
		l.Logger.Error("Invalid IP address", "ip", ip)
		return nil
	}

	// Search IPv4 prefixes
	for _, prefix := range ipRanges.Prefixes {
		_, ipNet, err := net.ParseCIDR(prefix.IPPrefix)
		if err != nil {
			l.Logger.Error("Error parsing CIDR", "cidr", prefix.IPPrefix, "error", err)
			continue
		}

		if ipNet.Contains(targetIP) {
			l.Logger.Info("Found matching AWS IP range",
				"ip", ip,
				"prefix", prefix.IPPrefix,
				"region", prefix.Region,
				"service", prefix.Service)
			return l.Send(prefix)
		}
	}

	// Search IPv6 prefixes if the target is IPv6
	if targetIP.To4() == nil {
		for _, prefix := range ipRanges.Ipv6 {
			_, ipNet, err := net.ParseCIDR(prefix.Ipv6Prefix)
			if err != nil {
				l.Logger.Error("Error parsing CIDR", "cidr", prefix.Ipv6Prefix, "error", err)
				continue
			}

			if ipNet.Contains(targetIP) {
				l.Logger.Info("Found matching AWS IPv6 range",
					"ip", ip,
					"prefix", prefix.Ipv6Prefix,
					"region", prefix.Region,
					"service", prefix.Service)
				return l.Send(prefix)
			}
		}
	}

	l.Logger.Info("IP not found in AWS ranges", "ip", ip)
	return nil
}
