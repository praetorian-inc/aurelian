package eiptakeover

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
)

const awsIPRangesURL = "https://ip-ranges.amazonaws.com/ip-ranges.json"

// ipPrefix holds a single IPv4 prefix entry from ip-ranges.json.
type ipPrefix struct {
	IPPrefix           string `json:"ip_prefix"`
	Region             string `json:"region"`
	Service            string `json:"service"`
	NetworkBorderGroup string `json:"network_border_group"`
}

// awsIPRangesJSON is the top-level structure of ip-ranges.json.
type awsIPRangesJSON struct {
	Prefixes []ipPrefix `json:"prefixes"`
}

// parsedPrefix holds a pre-parsed CIDR network alongside its metadata.
type parsedPrefix struct {
	network *net.IPNet
	region  string
	service string
}

// AWSIPRanges holds the parsed AWS IP ranges and supports IP lookup.
type AWSIPRanges struct {
	prefixes []parsedPrefix
}

// FetchAWSIPRanges downloads and parses the AWS IP ranges JSON.
func FetchAWSIPRanges() (*AWSIPRanges, error) {
	resp, err := http.Get(awsIPRangesURL) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("fetch aws ip ranges: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch aws ip ranges: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read aws ip ranges response: %w", err)
	}

	var raw awsIPRangesJSON
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse aws ip ranges: %w", err)
	}

	ranges := &AWSIPRanges{}
	for _, p := range raw.Prefixes {
		if p.IPPrefix == "" {
			continue
		}
		_, network, err := net.ParseCIDR(p.IPPrefix)
		if err != nil {
			continue // skip malformed entries
		}
		ranges.prefixes = append(ranges.prefixes, parsedPrefix{
			network: network,
			region:  p.Region,
			service: p.Service,
		})
	}

	return ranges, nil
}

// Contains checks whether the given IP falls within any AWS IP prefix.
// If found, it returns the matching region and service name.
func (r *AWSIPRanges) Contains(ip string) (region, service string, ok bool) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", "", false
	}

	for _, p := range r.prefixes {
		if p.network.Contains(parsed) {
			return p.region, p.service, true
		}
	}

	return "", "", false
}
