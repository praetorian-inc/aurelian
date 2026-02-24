package ebtakeover

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/output"
)

// ScanOptions configures an ebtakeover scan.
type ScanOptions struct {
	Profile     string
	ProfileDir  string
	Regions     []string
	Concurrency int
	AccountID   string
}

// DanglingRecord represents a Route53 CNAME record pointing to an unclaimed
// Elastic Beanstalk environment prefix, making it vulnerable to subdomain takeover.
type DanglingRecord struct {
	ZoneID       string
	ZoneName     string
	RecordName   string
	CNAMETarget  string
	EBRegion     string
	EBPrefix     string
	DNSAvailable bool
}

// ToRisk converts a DanglingRecord to an output.Risk finding.
func (d DanglingRecord) ToRisk(accountID string) output.Risk {
	target := output.NewCloudResource("aws", "us-east-1", "AWS::Route53::RecordSet", accountID, d.RecordName)
	target.DisplayName = d.RecordName
	target.Properties = map[string]any{
		"zone_id":      d.ZoneID,
		"zone_name":    d.ZoneName,
		"cname_target": d.CNAMETarget,
		"eb_region":    d.EBRegion,
		"eb_prefix":    d.EBPrefix,
	}

	refs := []string{
		"https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_CheckDNSAvailability.html",
		"https://labs.detectify.com/writeups/hostile-subdomain-takeover-using-heroku-github-desk-more/",
		"https://hackerone.com/reports/473888",
	}

	return output.Risk{
		Target: &target,
		Name:   "eb-subdomain-takeover",
		DNS:    d.RecordName,
		Status: "TH",
		Source: "aurelian-eb-takeover-scanner",
		Description: fmt.Sprintf(
			"Route53 CNAME record %q in hosted zone %q points to %q, which references an unclaimed "+
				"Elastic Beanstalk environment prefix %q in region %s. The DNS prefix is reported as available, "+
				"meaning an attacker can register a new Elastic Beanstalk environment with this prefix and serve "+
				"arbitrary content from your domain.",
			d.RecordName, d.ZoneName, d.CNAMETarget, d.EBPrefix, d.EBRegion,
		),
		Impact: "An attacker can claim the dangling Elastic Beanstalk CNAME prefix and serve malicious content " +
			"(phishing pages, malware, credential harvesting) under your organization's domain name. This can " +
			"lead to brand damage, session hijacking if cookies are scoped broadly, and potential OAuth/SAML " +
			"redirect abuse if the subdomain is trusted by identity providers.",
		Recommendation: "Remove the stale Route53 CNAME record " + d.RecordName + " pointing to " + d.CNAMETarget +
			". If the Elastic Beanstalk environment is still needed, recreate it with the original prefix " +
			"before removing the DNS record to prevent a window of opportunity for an attacker.",
		References: strings.Join(refs, "\n"),
	}
}
