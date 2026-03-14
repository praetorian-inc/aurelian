package dnstakeover

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// Route53Enumerator lists all DNS records from public hosted zones.
type Route53Enumerator struct {
	ctx  context.Context
	opts plugin.AWSCommonRecon
}

// NewRoute53Enumerator creates a Route53 record enumerator.
func NewRoute53Enumerator(ctx context.Context, opts plugin.AWSCommonRecon) *Route53Enumerator {
	return &Route53Enumerator{ctx: ctx, opts: opts}
}

// EnumerateAll is a pipeline-compatible method that lists all records from
// all public hosted zones. It accepts a dummy string input to satisfy
// pipeline.Pipe when used with pipeline.From("route53").
func (e *Route53Enumerator) EnumerateAll(_ string, out *pipeline.P[Route53Record]) error {
	cfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
		Region:     "us-east-1", // Route53 is global
		Profile:    e.opts.Profile,
		ProfileDir: e.opts.ProfileDir,
	})
	if err != nil {
		return fmt.Errorf("create route53 config: %w", err)
	}

	client := route53.NewFromConfig(cfg)
	return e.enumerateZones(e.ctx, client, out)
}

func (e *Route53Enumerator) enumerateZones(ctx context.Context, client *route53.Client, out *pipeline.P[Route53Record]) error {
	var marker *string
	for {
		input := &route53.ListHostedZonesInput{}
		if marker != nil {
			input.Marker = marker
		}

		resp, err := client.ListHostedZones(ctx, input)
		if err != nil {
			return fmt.Errorf("list hosted zones: %w", err)
		}

		for _, hz := range resp.HostedZones {
			if hz.Config != nil && hz.Config.PrivateZone {
				continue
			}

			zoneID := strings.TrimPrefix(aws.ToString(hz.Id), "/hostedzone/")
			zoneName := strings.TrimSuffix(aws.ToString(hz.Name), ".")

			if err := e.enumerateRecords(ctx, client, zoneID, zoneName, out); err != nil {
				slog.Warn("failed to enumerate zone records", "zone_id", zoneID, "zone_name", zoneName, "error", err)
			}
		}

		if !resp.IsTruncated {
			break
		}
		marker = resp.NextMarker
	}

	return nil
}

func (e *Route53Enumerator) enumerateRecords(ctx context.Context, client *route53.Client, zoneID, zoneName string, out *pipeline.P[Route53Record]) error {
	var startName *string
	var startType r53types.RRType

	for {
		input := &route53.ListResourceRecordSetsInput{
			HostedZoneId: aws.String(zoneID),
		}
		if startName != nil {
			input.StartRecordName = startName
			input.StartRecordType = startType
		}

		resp, err := client.ListResourceRecordSets(ctx, input)
		if err != nil {
			return fmt.Errorf("list record sets for zone %s: %w", zoneID, err)
		}

		for _, rrs := range resp.ResourceRecordSets {
			var values []string
			for _, rr := range rrs.ResourceRecords {
				if rr.Value != nil {
					values = append(values, aws.ToString(rr.Value))
				}
			}

			out.Send(Route53Record{
				ZoneID:     zoneID,
				ZoneName:   zoneName,
				RecordName: strings.TrimSuffix(aws.ToString(rrs.Name), "."),
				Type:       string(rrs.Type),
				Values:     values,
				IsAlias:    rrs.AliasTarget != nil,
			})
		}

		if !resp.IsTruncated {
			break
		}
		startName = resp.NextRecordName
		startType = resp.NextRecordType
	}

	return nil
}
