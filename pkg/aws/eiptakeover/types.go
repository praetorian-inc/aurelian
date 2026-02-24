package eiptakeover

import (
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/output"
)

// ScanOptions holds the configuration for an EIP dangling takeover scan.
type ScanOptions struct {
	Profile     string
	ProfileDir  string
	Regions     []string
	Concurrency int
	AccountID   string
}

// ARecord represents a Route53 A record with one or more IP addresses.
type ARecord struct {
	ZoneID     string
	ZoneName   string
	RecordName string
	IPs        []string
}

// DanglingARecord represents a Route53 A record whose IP is in AWS IP space
// but is not allocated as an Elastic IP in this account — indicating it was
// released and could be claimed by an attacker.
type DanglingARecord struct {
	ZoneID     string
	ZoneName   string
	RecordName string
	IP         string
	AWSService string // from ip-ranges.json, e.g. "AMAZON", "EC2"
	AWSRegion  string // from ip-ranges.json, e.g. "us-east-1"
}

// ToRisk converts a DanglingARecord into an output.Risk finding.
func (d DanglingARecord) ToRisk(accountID string) output.Risk {
	return output.Risk{
		Name:   "eip-dangling-a-record",
		Status: "TM",
		Source: "aurelian-eip-takeover-scanner",
		DNS:    fmt.Sprintf("%s/%s/%s", accountID, d.ZoneName, d.RecordName),
		Target: &output.CloudResource{
			Platform:     "aws",
			ResourceType: "AWS::Route53::RecordSet",
			ResourceID:   fmt.Sprintf("%s/%s/%s", d.ZoneID, d.ZoneName, d.RecordName),
			AccountRef:   accountID,
			IPs:          []string{d.IP},
		},
		Description: fmt.Sprintf(
			"Route53 A record %q in zone %q points to IP %s which falls within AWS IP space (%s, %s) but is not currently allocated as an Elastic IP in this account. The IP may have been released and is available for an attacker to claim.",
			d.RecordName, d.ZoneName, d.IP, d.AWSService, d.AWSRegion,
		),
		Impact: "An attacker can repeatedly allocate Elastic IPs until they obtain the specific IP address, then serve malicious content under the victim subdomain or intercept traffic. This grants full control over the dangling subdomain.",
		Recommendation: "Remove the stale A record for " + d.RecordName + " from hosted zone " + d.ZoneName + ", or re-allocate an Elastic IP for the specific address and associate it with the appropriate EC2 instance or load balancer.",
		References: "https://bishopfox.com/blog/fishing-the-aws-ip-pool-for-dangling-domains\nhttps://github.com/assetnote/ghostbuster\nhttps://kmsec.uk/blog/passive-takeover/",
	}
}
