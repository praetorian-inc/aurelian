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

var gcpHTTPClient = &utils.CachedHTTPClient{}

const gcpIPRangesURL = "https://www.gstatic.com/ipranges/cloud.json"

func init() {
	plugin.Register(&GCPIPLookupModule{})
}

type GCPIPLookupConfig struct {
	IP string `param:"ip" desc:"IP address to look up in GCP IP ranges" required:"true"`
}

type GCPIPLookupModule struct {
	GCPIPLookupConfig
}

func (m *GCPIPLookupModule) ID() string                { return "ip-lookup" }
func (m *GCPIPLookupModule) Name() string              { return "GCP IP Lookup" }
func (m *GCPIPLookupModule) Platform() plugin.Platform { return plugin.PlatformGCP }
func (m *GCPIPLookupModule) Category() plugin.Category { return plugin.CategoryAnalyze }
func (m *GCPIPLookupModule) OpsecLevel() string        { return "safe" }
func (m *GCPIPLookupModule) Authors() []string         { return []string{"Praetorian"} }

func (m *GCPIPLookupModule) Description() string {
	return "Looks up an IP address against the GCP published IP ranges to determine whether it belongs to Google Cloud, and if so, which service and region."
}

func (m *GCPIPLookupModule) References() []string {
	return []string{"https://www.gstatic.com/ipranges/cloud.json"}
}

func (m *GCPIPLookupModule) SupportedResourceTypes() []string { return nil }
func (m *GCPIPLookupModule) Parameters() any                  { return &m.GCPIPLookupConfig }

type gcpIPRangeMatch struct {
	IPPrefix   string `json:"ip_prefix,omitempty"`
	IPv6Prefix string `json:"ipv6_prefix,omitempty"`
	Service    string `json:"service"`
	Scope      string `json:"scope"`
}

func (m *GCPIPLookupModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	ip := net.ParseIP(m.IP)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", m.IP)
	}

	cfg.Info("fetching GCP IP ranges")

	ranges, err := fetchGCPIPRanges()
	if err != nil {
		return fmt.Errorf("fetching GCP IP ranges: %w", err)
	}

	match, found := findIPInGCPRanges(ip, ranges)

	var resultsJSON []byte
	if found {
		prefix := match.IPPrefix + match.IPv6Prefix
		cfg.Info("found match: %s (%s, %s)", prefix, match.Service, match.Scope)
		resultsJSON, err = json.Marshal(match)
	} else {
		cfg.Info("IP %s not found in GCP ranges", m.IP)
		resultsJSON, err = json.Marshal(map[string]string{"result": "not found"})
	}
	if err != nil {
		return fmt.Errorf("marshaling results: %w", err)
	}

	out.Send(output.AnalyzeResult{
		Module:  m.ID(),
		Input:   m.IP,
		Results: json.RawMessage(resultsJSON),
	})
	return nil
}

type gcpIPRanges struct {
	SyncToken    string `json:"syncToken"`
	CreationTime string `json:"creationTime"`
	Prefixes     []struct {
		IPv4Prefix string `json:"ipv4Prefix,omitempty"`
		IPv6Prefix string `json:"ipv6Prefix,omitempty"`
		Service    string `json:"service"`
		Scope      string `json:"scope"`
	} `json:"prefixes"`
}

func fetchGCPIPRanges() (*gcpIPRanges, error) {
	body, err := gcpHTTPClient.Get(gcpIPRangesURL)
	if err != nil {
		return nil, err
	}
	var ranges gcpIPRanges
	if err := json.Unmarshal(body, &ranges); err != nil {
		return nil, fmt.Errorf("parsing GCP IP ranges JSON: %w", err)
	}
	return &ranges, nil
}

func findIPInGCPRanges(ip net.IP, ranges *gcpIPRanges) (gcpIPRangeMatch, bool) {
	for _, prefix := range ranges.Prefixes {
		cidr := prefix.IPv4Prefix
		if cidr == "" {
			cidr = prefix.IPv6Prefix
		}
		if cidr == "" {
			continue
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return gcpIPRangeMatch{
				IPPrefix:   prefix.IPv4Prefix,
				IPv6Prefix: prefix.IPv6Prefix,
				Service:    prefix.Service,
				Scope:      prefix.Scope,
			}, true
		}
	}
	return gcpIPRangeMatch{}, false
}
