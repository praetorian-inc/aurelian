package eiptakeover

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
)

// route53API abstracts the Route53 API calls for testability.
type route53API interface {
	ListHostedZones(ctx context.Context, params *route53.ListHostedZonesInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error)
	ListResourceRecordSets(ctx context.Context, params *route53.ListResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
}

// FindARecords enumerates all Route53 public hosted zones and returns all
// non-alias A records found. Alias A records (which point to AWS service
// endpoints rather than raw IPs) are skipped.
func FindARecords(profile, profileDir string) ([]ARecord, error) {
	cfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
		Region:     "us-east-1", // Route53 is global; us-east-1 is the canonical endpoint
		Profile:    profile,
		ProfileDir: profileDir,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS config for route53: %w", err)
	}

	client := route53.NewFromConfig(cfg)
	return findARecords(client)
}

func findARecords(client route53API) ([]ARecord, error) {
	zones, err := listPublicHostedZones(client)
	if err != nil {
		return nil, err
	}

	var records []ARecord
	for _, zone := range zones {
		zoneRecords, err := listARecordsInZone(client, aws.ToString(zone.Id), aws.ToString(zone.Name))
		if err != nil {
			return nil, fmt.Errorf("zone %s: %w", aws.ToString(zone.Name), err)
		}
		records = append(records, zoneRecords...)
	}

	return records, nil
}

func listPublicHostedZones(client route53API) ([]r53types.HostedZone, error) {
	var zones []r53types.HostedZone
	var marker *string

	for {
		input := &route53.ListHostedZonesInput{}
		if marker != nil {
			input.Marker = marker
		}

		out, err := client.ListHostedZones(context.Background(), input)
		if err != nil {
			return nil, fmt.Errorf("list hosted zones: %w", err)
		}

		for _, z := range out.HostedZones {
			// Skip private hosted zones
			if z.Config != nil && z.Config.PrivateZone {
				continue
			}
			zones = append(zones, z)
		}

		if !out.IsTruncated {
			break
		}
		marker = out.NextMarker
	}

	return zones, nil
}

func listARecordsInZone(client route53API, zoneID, zoneName string) ([]ARecord, error) {
	// Strip the /hostedzone/ prefix if present
	cleanZoneID := zoneID
	if idx := strings.LastIndex(zoneID, "/"); idx >= 0 {
		cleanZoneID = zoneID[idx+1:]
	}

	var records []ARecord
	var nextName *string
	var nextType r53types.RRType

	for {
		input := &route53.ListResourceRecordSetsInput{
			HostedZoneId: aws.String(cleanZoneID),
		}
		if nextName != nil {
			input.StartRecordName = nextName
			input.StartRecordType = nextType
		}

		out, err := client.ListResourceRecordSets(context.Background(), input)
		if err != nil {
			return nil, fmt.Errorf("list record sets: %w", err)
		}

		for _, rrs := range out.ResourceRecordSets {
			// Only process A records
			if rrs.Type != r53types.RRTypeA {
				continue
			}
			// Skip alias records — they point to AWS service endpoints, not raw IPs
			if rrs.AliasTarget != nil {
				continue
			}

			var ips []string
			for _, rr := range rrs.ResourceRecords {
				if rr.Value != nil {
					ips = append(ips, aws.ToString(rr.Value))
				}
			}

			if len(ips) == 0 {
				continue
			}

			records = append(records, ARecord{
				ZoneID:     cleanZoneID,
				ZoneName:   zoneName,
				RecordName: aws.ToString(rrs.Name),
				IPs:        ips,
			})
		}

		if !out.IsTruncated {
			break
		}
		nextName = out.NextRecordName
		nextType = out.NextRecordType
	}

	return records, nil
}
