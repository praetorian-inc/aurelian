package nstakeover

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/output"
)

// ScanOptions configures an nstakeover scan.
type ScanOptions struct {
	Profile     string
	ProfileDir  string
	Concurrency int
	AccountID   string
}

// NSDelegation represents a Route53 NS delegation record found in a hosted zone.
// It identifies a subdomain delegated to Route53 nameservers.
type NSDelegation struct {
	ZoneID      string
	ZoneName    string
	RecordName  string
	Nameservers []string
}

// DanglingNSDelegation represents an NS delegation record whose delegated
// hosted zone no longer exists — the nameservers return SERVFAIL, REFUSED,
// or NXDOMAIN for the delegated subdomain.
type DanglingNSDelegation struct {
	ZoneID      string
	ZoneName    string
	RecordName  string
	Nameservers []string
	QueryError  string // describes the DNS error: SERVFAIL, REFUSED, or NXDOMAIN
}

// ToRisk converts a DanglingNSDelegation into an output.Risk finding.
func (d DanglingNSDelegation) ToRisk(accountID string) output.Risk {
	target := output.NewCloudResource("aws", "us-east-1", "AWS::Route53::RecordSet", accountID, d.RecordName)
	target.DisplayName = d.RecordName
	target.Properties = map[string]any{
		"zone_id":     d.ZoneID,
		"zone_name":   d.ZoneName,
		"nameservers": strings.Join(d.Nameservers, ", "),
		"query_error": d.QueryError,
	}

	refs := []string{
		"https://www.form3.tech/blog/engineering/dangling-danger",
		"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/protection-from-dangling-dns.html",
		"https://0xpatrik.com/subdomain-takeover-ns/",
	}

	return output.Risk{
		Target: &target,
		Name:   "ns-delegation-takeover",
		DNS:    d.RecordName,
		Status: "TH",
		Source: "aurelian-ns-takeover-scanner",
		Description: fmt.Sprintf(
			"Route53 NS delegation record %q in hosted zone %q delegates to Route53 nameservers "+
				"(%s), but the delegated hosted zone no longer exists (DNS query returned: %s). "+
				"Using the Form3 bypass technique, an attacker can create a new Route53 hosted zone "+
				"for the delegated subdomain and gain full DNS control over it.",
			d.RecordName, d.ZoneName,
			strings.Join(d.Nameservers, ", "),
			d.QueryError,
		),
		Impact: "An attacker with full DNS control over the delegated subdomain can create arbitrary " +
			"DNS records (A, MX, TXT, CNAME), enabling phishing pages under a trusted domain, " +
			"email impersonation, SPF bypass for spam, and subdomain takeover of any services " +
			"previously hosted at the delegated name.",
		Recommendation: "Remove the stale NS delegation record " + d.RecordName +
			" from hosted zone " + d.ZoneName + ". If the subdomain's hosted zone is still needed, " +
			"recreate it in Route53 before removing the delegation record to prevent a window of " +
			"opportunity for an attacker.",
		References: strings.Join(refs, "\n"),
	}
}
