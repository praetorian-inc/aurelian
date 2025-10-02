package cloudfront

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
)

// Route53DomainFinder finds Route53 records pointing to vulnerable CloudFront distributions
type Route53DomainFinder struct {
	*base.AwsReconLink
}

// Route53Record contains information about a Route53 record
type Route53Record struct {
	ZoneID     string `json:"zone_id"`
	ZoneName   string `json:"zone_name"`
	RecordName string `json:"record_name"`
	RecordType string `json:"record_type"`
	Value      string `json:"value"`
}

// S3TakeoverFinding contains the complete vulnerability finding
type S3TakeoverFinding struct {
	DistributionID     string          `json:"distribution_id"`
	DistributionDomain string          `json:"distribution_domain"`
	Aliases            []string        `json:"aliases,omitempty"`
	MissingBucket      string          `json:"missing_bucket"`
	OriginDomain       string          `json:"origin_domain"`
	OriginID           string          `json:"origin_id"`
	AccountID          string          `json:"account_id"`
	Region             string          `json:"region"`
	Route53Records     []Route53Record `json:"route53_records,omitempty"`
	AffectedDomains    []string        `json:"affected_domains"`
	Severity           string          `json:"severity"`
	Risk               string          `json:"risk"`
	Remediation        string          `json:"remediation"`
}

// NewRoute53DomainFinder creates a new Route53 domain finder
func NewRoute53DomainFinder(configs ...cfg.Config) chain.Link {
	finder := &Route53DomainFinder{}
	finder.AwsReconLink = base.NewAwsReconLink(finder, configs...)
	return finder
}

// Process finds Route53 records pointing to vulnerable distributions
func (r *Route53DomainFinder) Process(resource any) error {
	vuln, ok := resource.(VulnerableDistribution)
	if !ok {
		// Not a vulnerable distribution, pass through
		return r.Send(resource)
	}

	slog.Info("Searching Route53 for domains pointing to vulnerable CloudFront distribution",
		"distribution_id", vuln.DistributionID,
		"distribution_domain", vuln.DistributionDomain)

	// Route53 is a global service, use us-east-1
	config, err := r.GetConfigWithRuntimeArgs("us-east-1")
	if err != nil {
		return fmt.Errorf("failed to get AWS config: %w", err)
	}

	route53Client := route53.NewFromConfig(config)

	// Find all Route53 records pointing to this distribution
	records, err := r.findRoute53Records(route53Client, vuln.DistributionDomain, vuln.Aliases)
	if err != nil {
		slog.Warn("Error searching Route53 records", "error", err)
		// Don't fail completely, still report the vulnerability
		records = []Route53Record{}
	}

	// Build affected domains list
	affectedDomains := []string{}
	for _, record := range records {
		affectedDomains = append(affectedDomains, record.RecordName)
	}

	// Add aliases as potentially affected domains
	for _, alias := range vuln.Aliases {
		if !slices.Contains(affectedDomains, alias) {
			affectedDomains = append(affectedDomains, alias)
		}
	}

	// Create complete finding
	finding := S3TakeoverFinding{
		DistributionID:     vuln.DistributionID,
		DistributionDomain: vuln.DistributionDomain,
		Aliases:            vuln.Aliases,
		MissingBucket:      vuln.MissingBucket,
		OriginDomain:       vuln.OriginDomain,
		OriginID:           vuln.OriginID,
		AccountID:          vuln.AccountID,
		Region:             vuln.Region,
		Route53Records:     records,
		AffectedDomains:    affectedDomains,
		Severity:           "CRITICAL",
		Risk: fmt.Sprintf("CloudFront distribution %s points to non-existent S3 bucket '%s'. "+
			"An attacker could create this bucket to serve malicious content on %d domain(s): %s",
			vuln.DistributionID, vuln.MissingBucket, len(affectedDomains), strings.Join(affectedDomains, ", ")),
		Remediation: fmt.Sprintf("1. Delete the CloudFront distribution %s if no longer needed, OR\n"+
			"2. Create the S3 bucket '%s' in your account to reclaim ownership, OR\n"+
			"3. Update the distribution to point to a different origin",
			vuln.DistributionID, vuln.MissingBucket),
	}

	if len(records) > 0 {
		slog.Info("Found Route53 records pointing to vulnerable distribution",
			"distribution_id", vuln.DistributionID,
			"records", len(records),
			"affected_domains", affectedDomains)
	} else {
		slog.Info("No Route53 records found (DNS may be managed externally)",
			"distribution_id", vuln.DistributionID)
	}

	// Send complete finding
	return r.Send(finding)
}

// findRoute53Records finds all Route53 records pointing to a CloudFront distribution
func (r *Route53DomainFinder) findRoute53Records(client *route53.Client, cloudfrontDomain string, aliases []string) ([]Route53Record, error) {
	var matchingRecords []Route53Record

	// Normalize CloudFront domain
	cloudfrontDomain = strings.TrimSuffix(cloudfrontDomain, ".")

	// Get all hosted zones
	zonesPaginator := route53.NewListHostedZonesPaginator(client, &route53.ListHostedZonesInput{})

	for zonesPaginator.HasMorePages() {
		zonesPage, err := zonesPaginator.NextPage(context.TODO())
		if err != nil {
			slog.Warn("Failed to list hosted zones", "error", err)
			continue
		}

		for _, zone := range zonesPage.HostedZones {
			if zone.Id == nil || zone.Name == nil {
				continue
			}

			zoneID := strings.TrimPrefix(*zone.Id, "/hostedzone/")
			zoneName := strings.TrimSuffix(*zone.Name, ".")

			// Get all records in this zone
			recordsPaginator := route53.NewListResourceRecordSetsPaginator(client, &route53.ListResourceRecordSetsInput{
				HostedZoneId: &zoneID,
			})

			for recordsPaginator.HasMorePages() {
				recordsPage, err := recordsPaginator.NextPage(context.TODO())
				if err != nil {
					slog.Debug("Failed to list records in zone", "zone", zoneName, "error", err)
					continue
				}

				for _, record := range recordsPage.ResourceRecordSets {
					if record.Name == nil {
						continue
					}

					recordName := strings.TrimSuffix(*record.Name, ".")
					recordType := string(record.Type)

					// Check A and AAAA records with alias targets
					if (recordType == "A" || recordType == "AAAA") && record.AliasTarget != nil {
						if record.AliasTarget.DNSName != nil {
							aliasTarget := strings.TrimSuffix(*record.AliasTarget.DNSName, ".")

							// Check if this record points to our CloudFront distribution
							if aliasTarget == cloudfrontDomain {
								matchingRecords = append(matchingRecords, Route53Record{
									ZoneID:     zoneID,
									ZoneName:   zoneName,
									RecordName: recordName,
									RecordType: recordType,
									Value:      aliasTarget,
								})

								slog.Debug("Found Route53 alias record pointing to CloudFront",
									"record", recordName,
									"type", recordType,
									"target", aliasTarget)
							}
						}
					}

					// Check CNAME records
					if recordType == "CNAME" && record.ResourceRecords != nil {
						for _, rr := range record.ResourceRecords {
							if rr.Value != nil {
								cnameValue := strings.TrimSuffix(*rr.Value, ".")

								// Check if CNAME points to CloudFront distribution or one of its aliases
								if cnameValue == cloudfrontDomain || slices.Contains(aliases, cnameValue) {
									matchingRecords = append(matchingRecords, Route53Record{
										ZoneID:     zoneID,
										ZoneName:   zoneName,
										RecordName: recordName,
										RecordType: recordType,
										Value:      cnameValue,
									})

									slog.Debug("Found Route53 CNAME record pointing to CloudFront",
										"record", recordName,
										"target", cnameValue)
								}
							}
						}
					}
				}
			}
		}
	}

	return matchingRecords, nil
}
