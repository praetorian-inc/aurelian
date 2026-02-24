package ebtakeover

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

// ebCNAMEPattern matches Elastic Beanstalk CNAME targets.
// Captures: [1] prefix, [2] region (e.g. us-east-1)
var ebCNAMEPattern = regexp.MustCompile(`^([a-zA-Z0-9-]+)\.([a-z]{2}-[a-z]+-\d+)\.elasticbeanstalk\.com\.?$`)

// EBCandidate is a Route53 CNAME record that may point to an Elastic Beanstalk environment.
type EBCandidate struct {
	ZoneID      string
	ZoneName    string
	RecordName  string
	CNAMETarget string
	EBRegion    string
	EBPrefix    string
}

// route53API is the subset of the Route53 client used by this package.
type route53API interface {
	ListHostedZones(ctx context.Context, params *route53.ListHostedZonesInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error)
	ListResourceRecordSets(ctx context.Context, params *route53.ListResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
}

// hostedZone is a minimal representation of a public hosted zone.
type hostedZone struct {
	id   string
	name string
}

// FindEBCandidates enumerates all public Route53 hosted zones and returns
// CNAME records that match the Elastic Beanstalk CNAME pattern.
// Route53 is a global service so us-east-1 is used for the config region.
func FindEBCandidates(profile, profileDir string) ([]EBCandidate, error) {
	cfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
		Region:     "us-east-1",
		Profile:    profile,
		ProfileDir: profileDir,
	})
	if err != nil {
		return nil, fmt.Errorf("create route53 config: %w", err)
	}

	client := route53.NewFromConfig(cfg)
	return findCandidates(client)
}

// findCandidates is the internal implementation, separated for testability.
func findCandidates(client route53API) ([]EBCandidate, error) {
	zones, err := listPublicZones(client)
	if err != nil {
		return nil, fmt.Errorf("list hosted zones: %w", err)
	}

	var candidates []EBCandidate
	for _, z := range zones {
		zoneCandidate, err := scanZoneRecords(client, z)
		if err != nil {
			return nil, fmt.Errorf("scan zone %s: %w", z.id, err)
		}
		candidates = append(candidates, zoneCandidate...)
	}

	return candidates, nil
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

// scanZoneRecords paginates ListResourceRecordSets for a zone and returns
// any CNAME records matching the EB pattern.
func scanZoneRecords(client route53API, z hostedZone) ([]EBCandidate, error) {
	var candidates []EBCandidate
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
			if rrs.Type != r53types.RRTypeCname {
				continue
			}
			for _, rr := range rrs.ResourceRecords {
				val := aws.ToString(rr.Value)
				m := ebCNAMEPattern.FindStringSubmatch(val)
				if m == nil {
					continue
				}
				candidates = append(candidates, EBCandidate{
					ZoneID:      z.id,
					ZoneName:    strings.TrimSuffix(z.name, "."),
					RecordName:  strings.TrimSuffix(aws.ToString(rrs.Name), "."),
					CNAMETarget: val,
					EBRegion:    m[2],
					EBPrefix:    m[1],
				})
			}
		}

		if !out.IsTruncated {
			break
		}
		startName = out.NextRecordName
		startType = out.NextRecordType
	}

	return candidates, nil
}

// extractZoneID strips the /hostedzone/ prefix from a Route53 zone ID.
func extractZoneID(id string) string {
	return strings.TrimPrefix(id, "/hostedzone/")
}
