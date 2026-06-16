package enumeration

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// ClassicELBEnumerator enumerates Classic (v1) Elastic Load Balancers using the
// native elasticloadbalancing SDK because CloudControl does not support listing
// AWS::ElasticLoadBalancing::LoadBalancer (the type registers no handlers). It
// sets IsInternetFacing so the shared evaluateELBv2 evaluator handles it.
type ClassicELBEnumerator struct {
	plugin.AWSCommonRecon
	provider   *AWSConfigProvider
	skipReport *SkipReport
}

func NewClassicELBEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider, skipReport *SkipReport) *ClassicELBEnumerator {
	return &ClassicELBEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
		skipReport:     skipReport,
	}
}

func (e *ClassicELBEnumerator) ResourceType() string {
	return "AWS::ElasticLoadBalancing::LoadBalancer"
}

func (e *ClassicELBEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(e.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}
	// Account ID is resolved inside each region's own (already-validated) config
	// rather than from a single prerequisite region, so one disabled region does
	// not abort the whole enumeration.
	actor := ratelimit.NewCrossRegionActor(e.Concurrency)
	return actor.ActInRegions(e.Regions, func(region string) error {
		return e.listInRegion(region, out)
	})
}

func (e *ClassicELBEnumerator) EnumerateByARN(arn string, out *pipeline.P[output.AWSResource]) error {
	parsed, err := awsarn.Parse(arn)
	if err != nil {
		return fmt.Errorf("parse ARN %q: %w", arn, err)
	}
	name, ok := strings.CutPrefix(parsed.Resource, "loadbalancer/")
	if !ok {
		return fmt.Errorf("invalid Classic ELB ARN resource: %q", parsed.Resource)
	}
	if name == "" {
		return fmt.Errorf("missing load balancer name in Classic ELB ARN: %q", arn)
	}
	if parsed.Region == "" {
		return fmt.Errorf("missing region in Classic ELB ARN: %q", arn)
	}
	cfg, err := e.provider.GetAWSConfig(parsed.Region)
	if err != nil {
		return fmt.Errorf("create ELB client for %s: %w", parsed.Region, err)
	}
	client := elasticloadbalancing.NewFromConfig(*cfg)
	resp, err := client.DescribeLoadBalancers(context.Background(), &elasticloadbalancing.DescribeLoadBalancersInput{
		LoadBalancerNames: []string{name},
	})
	if err != nil {
		if op := ClassifySkippable(err, "elasticloadbalancing", "DescribeLoadBalancers", parsed.Region); op != nil {
			e.skipReport.RecordBatch([]SkippedOp{*op})
			return nil
		}
		return fmt.Errorf("describe Classic ELB %s: %w", name, err)
	}
	for _, lb := range resp.LoadBalancerDescriptions {
		e.send(parsed.Region, parsed.AccountID, lb, out)
	}
	return nil
}

func (e *ClassicELBEnumerator) listInRegion(region string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := e.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create ELB client for %s: %w", region, err)
	}
	accountID, err := awshelpers.GetAccountId(*cfg)
	if err != nil {
		if op := ClassifySkippable(err, "sts", "GetCallerIdentity", region); op != nil {
			e.skipReport.RecordBatch([]SkippedOp{*op})
			return nil
		}
		return fmt.Errorf("resolve account for %s: %w", region, err)
	}
	client := elasticloadbalancing.NewFromConfig(*cfg)

	var marker *string
	for {
		resp, err := client.DescribeLoadBalancers(context.Background(), &elasticloadbalancing.DescribeLoadBalancersInput{
			Marker: marker,
		})
		if err != nil {
			if op := ClassifySkippable(err, "elasticloadbalancing", "DescribeLoadBalancers", region); op != nil {
				e.skipReport.RecordBatch([]SkippedOp{*op})
				return nil
			}
			return fmt.Errorf("list Classic ELBs in %s: %w", region, err)
		}
		for _, lb := range resp.LoadBalancerDescriptions {
			e.send(region, accountID, lb, out)
		}
		if resp.NextMarker == nil {
			break
		}
		marker = resp.NextMarker
	}
	return nil
}

func (e *ClassicELBEnumerator) send(region, accountID string, lb elbtypes.LoadBalancerDescription, out *pipeline.P[output.AWSResource]) {
	name := aws.ToString(lb.LoadBalancerName)
	scheme := aws.ToString(lb.Scheme)
	out.Send(output.AWSResource{
		ResourceType: "AWS::ElasticLoadBalancing::LoadBalancer",
		ResourceID:   name,
		ARN:          fmt.Sprintf("arn:aws:elasticloadbalancing:%s:%s:loadbalancer/%s", region, accountID, name),
		AccountRef:   accountID,
		Region:       region,
		DisplayName:  name,
		Properties: map[string]any{
			"LoadBalancerName": name,
			"Scheme":           scheme,
			"DNSName":          aws.ToString(lb.DNSName),
			"IsInternetFacing": strings.EqualFold(scheme, "internet-facing"),
		},
	})
}
