package nstakeover

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
)

// nsRoute53Pattern matches Route53 nameservers of the form:
// ns-123.awsdns-45.com, ns-678.awsdns-90.org, ns-1234.awsdns-56.co.uk, etc.
var nsRoute53Pattern = regexp.MustCompile(`(?i)^ns-\d+\.awsdns-\d+\.\w+`)

// route53API abstracts the Route53 API calls for testability.
type route53API interface {
	ListHostedZones(ctx context.Context, params *route53.ListHostedZonesInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error)
	ListResourceRecordSets(ctx context.Context, params *route53.ListResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
}

// hostedZone is a minimal representation of a public hosted zone.
type hostedZone struct {
	id   string
	name string
}

// FindNSDelegations enumerates all Route53 public hosted zones and returns
// NS records that delegate to AWS Route53 nameservers, excluding apex NS records.
// Route53 is a global service so us-east-1 is used for the config region.
func FindNSDelegations(profile, profileDir string) ([]NSDelegation, error) {
	cfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
		Region:     "us-east-1",
		Profile:    profile,
		ProfileDir: profileDir,
	})
	if err != nil {
		return nil, fmt.Errorf("create route53 config: %w", err)
	}

	client := route53.NewFromConfig(cfg)
	return findNSDelegations(client)
}

// findNSDelegations is the internal implementation, separated for testability.
func findNSDelegations(client route53API) ([]NSDelegation, error) {
	zones, err := listPublicZones(client)
	if err != nil {
		return nil, fmt.Errorf("list hosted zones: %w", err)
	}

	var delegations []NSDelegation
	for _, z := range zones {
		zoneDelegations, err := scanZoneForNSDelegations(client, z)
		if err != nil {
			return nil, fmt.Errorf("scan zone %s: %w", z.id, err)
		}
		delegations = append(delegations, zoneDelegations...)
	}

	return delegations, nil
}

// listPublicZones paginates ListHostedZones and returns only public zones.
func listPublicZones(client route53API) ([]hostedZone, error) {
	var zones []hostedZone
	var marker *string

	for {
		input := &route53.ListHostedZonesInput{}
		if marker != nil {
			input.Marker = marker
		}

		out, err := client.ListHostedZones(context.Background(), input)
		if err != nil {
			return nil, err
		}

		for _, hz := range out.HostedZones {
			// Skip private zones — they are not publicly resolvable.
			if hz.Config != nil && hz.Config.PrivateZone {
				continue
			}
			zones = append(zones, hostedZone{
				id:   extractZoneID(aws.ToString(hz.Id)),
				name: aws.ToString(hz.Name),
			})
		}

		if !out.IsTruncated {
			break
		}
		marker = out.NextMarker
	}

	return zones, nil
}

// scanZoneForNSDelegations paginates ListResourceRecordSets for a zone and
// returns NS records that delegate to Route53 nameservers, skipping apex NS records.
func scanZoneForNSDelegations(client route53API, z hostedZone) ([]NSDelegation, error) {
	// Normalize zone name for apex comparison (strip trailing dot)
	zoneName := strings.TrimSuffix(z.name, ".")

	var delegations []NSDelegation
	var startName *string
	var startType r53types.RRType

	for {
		input := &route53.ListResourceRecordSetsInput{
			HostedZoneId: aws.String(z.id),
		}
		if startName != nil {
			input.StartRecordName = startName
			input.StartRecordType = startType
		}

		out, err := client.ListResourceRecordSets(context.Background(), input)
		if err != nil {
			return nil, err
		}

		for _, rrs := range out.ResourceRecordSets {
			if rrs.Type != r53types.RRTypeNs {
				continue
			}

			// Normalize record name for apex comparison (strip trailing dot)
			recordName := strings.TrimSuffix(aws.ToString(rrs.Name), ".")

			// CRITICAL: Skip NS records at the zone apex.
			// The zone apex NS records are the zone's own nameservers, not delegations.
			if recordName == zoneName {
				continue
			}

			// Collect nameservers that match the Route53 pattern
			var route53NSes []string
			for _, rr := range rrs.ResourceRecords {
				ns := strings.TrimSuffix(aws.ToString(rr.Value), ".")
				if nsRoute53Pattern.MatchString(ns) {
					route53NSes = append(route53NSes, ns)
				}
			}

			// Only include NS records that delegate to Route53 nameservers
			if len(route53NSes) == 0 {
				continue
			}

			delegations = append(delegations, NSDelegation{
				ZoneID:      z.id,
				ZoneName:    zoneName,
				RecordName:  recordName,
				Nameservers: route53NSes,
			})
		}

		if !out.IsTruncated {
			break
		}
		startName = out.NextRecordName
		startType = out.NextRecordType
	}

	return delegations, nil
}

// extractZoneID strips the /hostedzone/ prefix from a Route53 zone ID.
func extractZoneID(id string) string {
	return strings.TrimPrefix(id, "/hostedzone/")
}
