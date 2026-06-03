package cloudfront

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/capability-sdk/pkg/capmodel"
)

const riskName = "CloudFront S3 Origin Takeover"

// TakeoverReferences lists external write-ups describing CloudFront/S3 origin
// takeover. This is the single source of truth; the module's References() returns it.
var TakeoverReferences = []string{
	"https://labs.detectify.com/writeups/hostile-subdomain-takeover-using-cloudfront/",
	"https://www.hackerone.com/application-security/guide-subdomain-takeovers",
	"https://github.com/EdOverflow/can-i-take-over-xyz",
}

// NewTakeoverRisk builds a platform capmodel.Risk for a CloudFront S3 origin
// takeover finding. Severity is Medium by default, High when Route53 records
// actively point at the distribution, and Critical when the referenced bucket
// exists under another account (active takeover).
func NewTakeoverRisk(f Finding) (capmodel.Risk, error) {
	severity := output.RiskSeverityMedium
	if len(f.Route53Records) > 0 {
		severity = output.RiskSeverityHigh
	}
	if f.BucketState == BucketExistsNotOwned {
		severity = output.RiskSeverityCritical
	}

	affectedDomains := collectAffectedDomains(f.Aliases, f.Route53Records)

	targetName := f.DistributionDomain
	if len(affectedDomains) > 0 {
		targetName = affectedDomains[0]
	}

	proof, err := json.Marshal(buildTakeoverProof(f, affectedDomains))
	if err != nil {
		return capmodel.Risk{}, err
	}

	return capmodel.Risk{
		TargetName: targetName,
		Name:       riskName,
		Source:     "aurelian",
		Status:     severityToStatus(severity),
		Proof:      proof,
		// TODO(LAB-3740): populate a typed capmodel asset (e.g. capmodel.Domain for the
		// affected domain, or capmodel.AwsResource for the distribution) once Aurelian emits
		// the SDK `_type` envelope and Guard's ingest consumes Risk.Target. Inert until then —
		// Guard's convertRisk falls back to a bare Asset without a `_type` discriminator.
		Target: nil,
	}, nil
}

// buildTakeoverProof assembles the structured proof: a summary, distribution
// details, affected domains (with a Route53 table when present), impact,
// recommendation, and references.
func buildTakeoverProof(f Finding, affectedDomains []string) capmodel.Proof {
	description := takeoverDescription(f, affectedDomains)
	impact := takeoverImpact(f)
	recommendation := takeoverRecommendation(f)

	sections := []capmodel.ProofSection{
		{Title: "Summary", Elements: []capmodel.ProofElement{paragraph(description)}},
		{Title: "Distribution Details", Elements: []capmodel.ProofElement{distributionKeyValue(f)}},
	}

	if len(affectedDomains) > 0 {
		elements := []capmodel.ProofElement{list(affectedDomains)}
		if len(f.Route53Records) > 0 {
			elements = append(elements, route53Table(f.Route53Records))
		}
		sections = append(sections, capmodel.ProofSection{Title: "Affected Domains", Elements: elements})
	}

	sections = append(sections,
		capmodel.ProofSection{Title: "Impact", Elements: []capmodel.ProofElement{paragraph(impact)}},
		capmodel.ProofSection{Title: "Recommendation", Elements: []capmodel.ProofElement{list(recommendation)}},
		capmodel.ProofSection{Title: "References", Elements: []capmodel.ProofElement{referenceList(TakeoverReferences)}},
	)

	return capmodel.Proof{Format: "v1.0.0", Sections: sections}
}

// severityToStatus maps a risk severity to a Chariot triage status code.
func severityToStatus(sev output.RiskSeverity) string {
	switch output.NormalizeSeverity(sev) {
	case output.RiskSeverityCritical:
		return "TC"
	case output.RiskSeverityHigh:
		return "TH"
	case output.RiskSeverityMedium:
		return "TM"
	case output.RiskSeverityLow:
		return "TL"
	default:
		return "TI"
	}
}

func takeoverDescription(f Finding, affectedDomains []string) string {
	if f.BucketState == BucketExistsNotOwned {
		desc := fmt.Sprintf(
			"CloudFront distribution %s references S3 bucket '%s' which exists but is not owned by this account. "+
				"An external party may already be serving content through this distribution.",
			f.DistributionID, f.MissingBucket,
		)
		if len(affectedDomains) > 0 {
			desc += fmt.Sprintf(" Affected domain(s): %s", strings.Join(affectedDomains, ", "))
		}
		return desc
	}

	if len(f.Route53Records) > 0 {
		return fmt.Sprintf(
			"CloudFront distribution %s points to non-existent S3 bucket '%s'. "+
				"Route53 records are actively pointing to this distribution. "+
				"An attacker could create this bucket to serve malicious content on %d domain(s): %s",
			f.DistributionID, f.MissingBucket,
			len(affectedDomains), strings.Join(affectedDomains, ", "),
		)
	}
	if len(affectedDomains) > 0 {
		return fmt.Sprintf(
			"CloudFront distribution %s points to non-existent S3 bucket '%s'. "+
				"An attacker could create this bucket to serve malicious content on alias domain(s): %s",
			f.DistributionID, f.MissingBucket,
			strings.Join(affectedDomains, ", "),
		)
	}
	return fmt.Sprintf(
		"CloudFront distribution %s points to non-existent S3 bucket '%s'. "+
			"An attacker could create this bucket to serve malicious content.",
		f.DistributionID, f.MissingBucket,
	)
}

func takeoverImpact(f Finding) string {
	if f.BucketState == BucketExistsNotOwned {
		return "The S3 bucket referenced by this distribution exists but is owned by another account. " +
			"An external party may already be serving arbitrary content through the CloudFront distribution."
	}
	return "An attacker could register the missing S3 bucket and serve arbitrary content " +
		"through the CloudFront distribution, enabling subdomain or domain takeover."
}

func takeoverRecommendation(f Finding) []string {
	if f.BucketState == BucketExistsNotOwned {
		return []string{
			fmt.Sprintf("Investigate content currently being served through distribution %s immediately", f.DistributionID),
			"Update the distribution origin to a bucket owned by this account, OR",
			fmt.Sprintf("Delete the CloudFront distribution %s and remove associated DNS records", f.DistributionID),
		}
	}
	return []string{
		fmt.Sprintf("Delete the CloudFront distribution %s if no longer needed, OR", f.DistributionID),
		fmt.Sprintf("Create the S3 bucket '%s' in your account to reclaim ownership, OR", f.MissingBucket),
		"Update the distribution to point to a different, existing origin.",
	}
}

func distributionKeyValue(f Finding) capmodel.ProofElement {
	bucketState := "missing"
	if f.BucketState == BucketExistsNotOwned {
		bucketState = "not_owned"
	}
	return keyValue([]capmodel.ProofKeyValueRow{
		{Key: "Distribution ID", Value: f.DistributionID, Copyable: true},
		{Key: "Distribution Domain", Value: f.DistributionDomain, Copyable: true},
		{Key: "Missing Bucket", Value: f.MissingBucket, Copyable: true},
		{Key: "Origin Domain", Value: f.OriginDomain},
		{Key: "Origin ID", Value: f.OriginID},
		{Key: "Bucket State", Value: bucketState},
	})
}

func route53Table(records []Route53Record) capmodel.ProofElement {
	rows := make([]map[string]string, 0, len(records))
	for _, r := range records {
		rows = append(rows, map[string]string{
			"record_name": r.RecordName,
			"record_type": r.RecordType,
			"value":       r.Value,
			"zone_name":   r.ZoneName,
		})
	}
	return capmodel.ProofElement{
		Type: "table",
		Table: &capmodel.ProofTable{
			Columns: []capmodel.ProofTableColumn{
				{Key: "record_name", Label: "Record Name"},
				{Key: "record_type", Label: "Type"},
				{Key: "value", Label: "Value"},
				{Key: "zone_name", Label: "Zone"},
			},
			Rows: rows,
		},
	}
}

// collectAffectedDomains returns the de-duplicated set of domains pointing at
// the distribution, with Route53 record names taking precedence over aliases.
func collectAffectedDomains(aliases []string, records []Route53Record) []string {
	seen := make(map[string]bool)
	var domains []string

	for _, r := range records {
		if !seen[r.RecordName] {
			seen[r.RecordName] = true
			domains = append(domains, r.RecordName)
		}
	}
	for _, alias := range aliases {
		if !seen[alias] {
			seen[alias] = true
			domains = append(domains, alias)
		}
	}
	return domains
}

func paragraph(text string) capmodel.ProofElement {
	return capmodel.ProofElement{Type: "paragraph", Paragraph: &capmodel.ProofParagraph{Text: text}}
}

func keyValue(rows []capmodel.ProofKeyValueRow) capmodel.ProofElement {
	return capmodel.ProofElement{Type: "key_value", KeyValue: &capmodel.ProofKeyValue{Rows: rows}}
}

func list(items []string) capmodel.ProofElement {
	listItems := make([]capmodel.ProofListItem, 0, len(items))
	for _, item := range items {
		listItems = append(listItems, capmodel.ProofListItem{Label: item})
	}
	return capmodel.ProofElement{Type: "list", List: &capmodel.ProofList{Items: listItems}}
}

func referenceList(urls []string) capmodel.ProofElement {
	items := make([]capmodel.ProofListItem, 0, len(urls))
	for _, u := range urls {
		items = append(items, capmodel.ProofListItem{Label: u, Href: u})
	}
	return capmodel.ProofElement{Type: "list", List: &capmodel.ProofList{Items: items}}
}
