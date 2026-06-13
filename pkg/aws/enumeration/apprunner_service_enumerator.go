package enumeration

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
	apprunnertypes "github.com/aws/aws-sdk-go-v2/service/apprunner/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// AppRunnerServiceEnumerator enumerates App Runner services using the native App Runner
// SDK. Services have no resource policy; they are emitted so the resource_service_role
// enricher can link a service to the IAM role its instances RUN AS
// (InstanceConfiguration.InstanceRoleArn) via a (Service)-[:HAS_ROLE]->(Role) edge,
// which the apprunner privesc methods re-point their CAN_PRIVESC edge at.
//
// ListServices summaries do NOT include the instance role, so each service is described
// per-ARN via DescribeService.
type AppRunnerServiceEnumerator struct {
	plugin.AWSCommonRecon
	provider   *AWSConfigProvider
	skipReport *SkipReport
}

// NewAppRunnerServiceEnumerator creates an AppRunnerServiceEnumerator that uses the native App Runner SDK.
func NewAppRunnerServiceEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider, skipReport *SkipReport) *AppRunnerServiceEnumerator {
	return &AppRunnerServiceEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
		skipReport:     skipReport,
	}
}

// ResourceType returns the CloudControl type string for App Runner services.
func (l *AppRunnerServiceEnumerator) ResourceType() string {
	return "AWS::AppRunner::Service"
}

// EnumerateAll enumerates all App Runner services owned by the account across configured regions.
func (l *AppRunnerServiceEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(l.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	accountID, err := l.provider.GetAccountID(l.Regions[0])
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	actor := ratelimit.NewCrossRegionActor(l.Concurrency)
	return actor.ActInRegions(l.Regions, func(region string) error {
		return l.listServicesInRegion(region, accountID, out)
	})
}

func (l *AppRunnerServiceEnumerator) listServicesInRegion(region, accountID string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := l.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create App Runner client for %s: %w", region, err)
	}
	client := apprunner.NewFromConfig(*cfg)

	paginator := apprunner.NewListServicesPaginator(client, &apprunner.ListServicesInput{})
	var skipped []SkippedOp
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if op := ClassifySkippable(err, "apprunner", "ListServices", region); op != nil {
				skipped = append(skipped, *op)
				break
			}
			return fmt.Errorf("list services in %s: %w", region, err)
		}
		for _, summary := range page.ServiceSummaryList {
			arn := aws.ToString(summary.ServiceArn)
			if arn == "" {
				continue
			}
			// The summary carries the ARN but NOT the instance role; describe per-ARN.
			detail, err := client.DescribeService(context.Background(), &apprunner.DescribeServiceInput{
				ServiceArn: summary.ServiceArn,
			})
			if err != nil {
				if op := ClassifySkippable(err, "apprunner", "DescribeService", region); op != nil {
					skipped = append(skipped, *op)
					continue
				}
				return fmt.Errorf("describe service %s in %s: %w", arn, region, err)
			}
			if detail.Service == nil {
				continue
			}
			out.Send(buildAppRunnerServiceResource(detail.Service, accountID, region))
		}
	}

	l.skipReport.RecordBatch(skipped)
	return nil
}

func buildAppRunnerServiceResource(service *apprunnertypes.Service, accountID, region string) output.AWSResource {
	name := aws.ToString(service.ServiceName)
	id := aws.ToString(service.ServiceId)

	// ServiceArn is the full ARN; fall back to a synthesized ARN if absent so the node
	// still keys cleanly (DescribeService always returns the ARN).
	arn := aws.ToString(service.ServiceArn)
	if arn == "" {
		arn = fmt.Sprintf("arn:aws:apprunner:%s:%s:service/%s/%s", region, accountID, name, id)
	}

	var instanceRoleArn string
	if service.InstanceConfiguration != nil {
		instanceRoleArn = aws.ToString(service.InstanceConfiguration.InstanceRoleArn)
	}

	return output.AWSResource{
		ResourceType: "AWS::AppRunner::Service",
		ResourceID:   name,
		ARN:          arn,
		AccountRef:   accountID,
		Region:       region,
		DisplayName:  name,
		Properties: map[string]any{
			"ServiceName": name,
			"ServiceId":   id,
			// InstanceRoleArn is the role the service's instances assume;
			// resource_service_role.yaml substring-matches this quoted ARN value inside the
			// flattened `properties` JSON string to create the (Service)-[:HAS_ROLE]->(Role) edge.
			"InstanceRoleArn": instanceRoleArn,
		},
	}
}
