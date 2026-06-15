package enumeration

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// OpenSearchDomainEnumerator enumerates OpenSearch and legacy Elasticsearch
// domains using the native OpenSearch SDK because CloudControl does not support
// listing AWS::OpenSearchService::Domain or AWS::Elasticsearch::Domain (neither
// type registers a list handler). The unified ListDomainNames API returns both
// engine types, which are reported under AWS::OpenSearchService::Domain.
type OpenSearchDomainEnumerator struct {
	plugin.AWSCommonRecon
	provider   *AWSConfigProvider
	skipReport *SkipReport
}

func NewOpenSearchDomainEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider, skipReport *SkipReport) *OpenSearchDomainEnumerator {
	return &OpenSearchDomainEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
		skipReport:     skipReport,
	}
}

func (e *OpenSearchDomainEnumerator) ResourceType() string {
	return "AWS::OpenSearchService::Domain"
}

func (e *OpenSearchDomainEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(e.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	accountID, err := e.provider.GetAccountID(e.Regions[0])
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	actor := ratelimit.NewCrossRegionActor(e.Concurrency)
	return actor.ActInRegions(e.Regions, func(region string) error {
		return e.listDomainsInRegion(region, accountID, out)
	})
}

func (e *OpenSearchDomainEnumerator) EnumerateByARN(arn string, out *pipeline.P[output.AWSResource]) error {
	parsed, err := awsarn.Parse(arn)
	if err != nil {
		return fmt.Errorf("parse ARN %q: %w", arn, err)
	}
	name, ok := strings.CutPrefix(parsed.Resource, "domain/")
	if !ok {
		return fmt.Errorf("invalid OpenSearch domain ARN resource: %q", parsed.Resource)
	}
	if parsed.Region == "" {
		return fmt.Errorf("OpenSearch domain ARN missing region: %q", arn)
	}

	cfg, err := e.provider.GetAWSConfig(parsed.Region)
	if err != nil {
		return fmt.Errorf("create OpenSearch client for %s: %w", parsed.Region, err)
	}
	client := opensearch.NewFromConfig(*cfg)
	return e.describeAndSend(client, parsed.Region, parsed.AccountID, name, out)
}

func (e *OpenSearchDomainEnumerator) listDomainsInRegion(region, accountID string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := e.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create OpenSearch client for %s: %w", region, err)
	}
	client := opensearch.NewFromConfig(*cfg)

	names, err := client.ListDomainNames(context.Background(), &opensearch.ListDomainNamesInput{})
	if err != nil {
		if op := ClassifySkippable(err, "es", "ListDomainNames", region); op != nil {
			e.skipReport.RecordBatch([]SkippedOp{*op})
			return nil
		}
		return fmt.Errorf("list OpenSearch domains in %s: %w", region, err)
	}

	var skipped []SkippedOp
	for _, info := range names.DomainNames {
		if err := e.describeAndSend(client, region, accountID, aws.ToString(info.DomainName), out); err != nil {
			if op := ClassifySkippable(err, "es", "DescribeDomain", region); op != nil {
				skipped = append(skipped, *op)
				continue
			}
			e.skipReport.RecordBatch(skipped)
			return err
		}
	}
	e.skipReport.RecordBatch(skipped)
	return nil
}

func (e *OpenSearchDomainEnumerator) describeAndSend(client *opensearch.Client, region, accountID, name string, out *pipeline.P[output.AWSResource]) error {
	result, err := client.DescribeDomain(context.Background(), &opensearch.DescribeDomainInput{
		DomainName: aws.String(name),
	})
	if err != nil {
		return fmt.Errorf("describe OpenSearch domain %s: %w", name, err)
	}
	d := result.DomainStatus
	if d == nil {
		return nil
	}

	fgacEnabled := false
	if d.AdvancedSecurityOptions != nil {
		fgacEnabled = aws.ToBool(d.AdvancedSecurityOptions.Enabled)
	}

	// A non-nil VPCOptions means the domain is VPC-scoped (reachable only from
	// within its VPC) rather than exposed on a public endpoint. The evaluator
	// uses this to describe the blast radius accurately.
	vpcScoped := d.VPCOptions != nil

	out.Send(output.AWSResource{
		ResourceType: "AWS::OpenSearchService::Domain",
		ResourceID:   aws.ToString(d.DomainName),
		ARN:          aws.ToString(d.ARN),
		AccountRef:   accountID,
		Region:       region,
		DisplayName:  aws.ToString(d.DomainName),
		Properties: map[string]any{
			"DomainName":              aws.ToString(d.DomainName),
			"EngineVersion":           aws.ToString(d.EngineVersion),
			"Endpoint":                aws.ToString(d.Endpoint),
			"AccessPolicies":          aws.ToString(d.AccessPolicies),
			"AdvancedSecurityOptions": map[string]any{"Enabled": fgacEnabled},
			"VPCScoped":               vpcScoped,
		},
	})
	return nil
}
