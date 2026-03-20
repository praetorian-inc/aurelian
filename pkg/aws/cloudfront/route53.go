package cloudfront

import (
	"context"
	"log/slog"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/route53"
)

// Route53API defines the Route53 operations required for finding DNS records
// pointing to CloudFront distributions. It is satisfied by *route53.Client.
type Route53API interface {
	ListHostedZones(ctx context.Context, params *route53.ListHostedZonesInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error)
	ListResourceRecordSets(ctx context.Context, params *route53.ListResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
}

// findRoute53Records searches all Route53 hosted zones for DNS records that
// point to the given CloudFront distribution domain or any of its aliases.
// It returns A/AAAA alias records whose AliasTarget matches cloudfrontDomain,
// and CNAME records whose value matches cloudfrontDomain or any alias.
func findRoute53Records(ctx context.Context, client Route53API, cloudfrontDomain string, aliases []string) []Route53Record {
	var matchingRecords []Route53Record
	cloudfrontDomain = strings.TrimSuffix(cloudfrontDomain, ".")

	zonesPaginator := route53.NewListHostedZonesPaginator(client, &route53.ListHostedZonesInput{})
	for zonesPaginator.HasMorePages() {
		zonesPage, err := zonesPaginator.NextPage(ctx)
		if err != nil {
			slog.WarnContext(ctx, "failed to retrieve hosted zones, aborting zone enumeration", "error", err)
			break
		}

		for _, zone := range zonesPage.HostedZones {
			if zone.Id == nil || zone.Name == nil {
				continue
			}
			zoneID := strings.TrimPrefix(*zone.Id, "/hostedzone/")
			zoneName := strings.TrimSuffix(*zone.Name, ".")

			recordsPaginator := route53.NewListResourceRecordSetsPaginator(client, &route53.ListResourceRecordSetsInput{
				HostedZoneId: &zoneID,
			})
			for recordsPaginator.HasMorePages() {
				recordsPage, err := recordsPaginator.NextPage(ctx)
				if err != nil {
					slog.WarnContext(ctx, "failed to retrieve record sets, skipping zone", "zoneID", zoneID, "error", err)
					break
				}

				for _, record := range recordsPage.ResourceRecordSets {
					if record.Name == nil {
						continue
					}
					recordName := strings.TrimSuffix(*record.Name, ".")
					recordType := string(record.Type)

					if (recordType == "A" || recordType == "AAAA") && record.AliasTarget != nil {
						if record.AliasTarget.DNSName != nil {
							aliasTarget := strings.TrimSuffix(*record.AliasTarget.DNSName, ".")
							if aliasTarget == cloudfrontDomain {
								matchingRecords = append(matchingRecords, Route53Record{
									ZoneID:     zoneID,
									ZoneName:   zoneName,
									RecordName: recordName,
									RecordType: recordType,
									Value:      aliasTarget,
								})
							}
						}
					}

					if recordType == "CNAME" && record.ResourceRecords != nil {
						for _, rr := range record.ResourceRecords {
							if rr.Value != nil {
								cnameValue := strings.TrimSuffix(*rr.Value, ".")
								if cnameValue == cloudfrontDomain || slices.Contains(aliases, cnameValue) {
									matchingRecords = append(matchingRecords, Route53Record{
										ZoneID:     zoneID,
										ZoneName:   zoneName,
										RecordName: recordName,
										RecordType: recordType,
										Value:      cnameValue,
									})
								}
							}
						}
					}
				}
			}
		}
	}

	return matchingRecords
}
