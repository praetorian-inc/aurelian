package enumeration

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// SageMakerNotebookInstanceEnumerator enumerates SageMaker notebook instances using the
// native SageMaker SDK. Notebook instances have no resource policy; they are emitted so
// the resource_service_role enricher can link an instance to the IAM role it RUNS AS
// (DescribeNotebookInstance.RoleArn) via a (NotebookInstance)-[:HAS_ROLE]->(Role) edge,
// which the sagemaker privesc methods re-point their CAN_PRIVESC edge at.
//
// ListNotebookInstances summaries do NOT include the role, so each is described per-name
// via DescribeNotebookInstance.
type SageMakerNotebookInstanceEnumerator struct {
	plugin.AWSCommonRecon
	provider   *AWSConfigProvider
	skipReport *SkipReport
}

// NewSageMakerNotebookInstanceEnumerator creates a SageMakerNotebookInstanceEnumerator that uses the native SageMaker SDK.
func NewSageMakerNotebookInstanceEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider, skipReport *SkipReport) *SageMakerNotebookInstanceEnumerator {
	return &SageMakerNotebookInstanceEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
		skipReport:     skipReport,
	}
}

// ResourceType returns the CloudControl type string for SageMaker notebook instances.
func (l *SageMakerNotebookInstanceEnumerator) ResourceType() string {
	return "AWS::SageMaker::NotebookInstance"
}

// EnumerateAll enumerates all SageMaker notebook instances owned by the account across configured regions.
func (l *SageMakerNotebookInstanceEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(l.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	accountID, err := l.provider.GetAccountID(l.Regions[0])
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	actor := ratelimit.NewCrossRegionActor(l.Concurrency)
	return actor.ActInRegions(l.Regions, func(region string) error {
		return l.listNotebookInstancesInRegion(region, accountID, out)
	})
}

func (l *SageMakerNotebookInstanceEnumerator) listNotebookInstancesInRegion(region, accountID string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := l.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create SageMaker client for %s: %w", region, err)
	}
	client := sagemaker.NewFromConfig(*cfg)

	paginator := sagemaker.NewListNotebookInstancesPaginator(client, &sagemaker.ListNotebookInstancesInput{})
	var skipped []SkippedOp
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if op := ClassifySkippable(err, "sagemaker", "ListNotebookInstances", region); op != nil {
				skipped = append(skipped, *op)
				break
			}
			return fmt.Errorf("list notebook instances in %s: %w", region, err)
		}
		for _, summary := range page.NotebookInstances {
			name := aws.ToString(summary.NotebookInstanceName)
			if name == "" {
				continue
			}
			// The summary carries the ARN but NOT the role; describe per-name.
			detail, err := client.DescribeNotebookInstance(context.Background(), &sagemaker.DescribeNotebookInstanceInput{
				NotebookInstanceName: summary.NotebookInstanceName,
			})
			if err != nil {
				if op := ClassifySkippable(err, "sagemaker", "DescribeNotebookInstance", region); op != nil {
					skipped = append(skipped, *op)
					continue
				}
				return fmt.Errorf("describe notebook instance %s in %s: %w", name, region, err)
			}
			out.Send(buildSageMakerNotebookInstanceResource(detail, accountID, region))
		}
	}

	l.skipReport.RecordBatch(skipped)
	return nil
}

func buildSageMakerNotebookInstanceResource(detail *sagemaker.DescribeNotebookInstanceOutput, accountID, region string) output.AWSResource {
	name := aws.ToString(detail.NotebookInstanceName)

	// NotebookInstanceArn is the full ARN; fall back to a synthesized ARN if absent so the
	// node still keys cleanly (DescribeNotebookInstance always returns the ARN).
	arn := aws.ToString(detail.NotebookInstanceArn)
	if arn == "" {
		arn = fmt.Sprintf("arn:aws:sagemaker:%s:%s:notebook-instance/%s", region, accountID, name)
	}

	return output.AWSResource{
		ResourceType: "AWS::SageMaker::NotebookInstance",
		ResourceID:   name,
		ARN:          arn,
		AccountRef:   accountID,
		Region:       region,
		DisplayName:  name,
		Properties: map[string]any{
			"NotebookInstanceName": name,
			// RoleArn is the role the notebook instance assumes; resource_service_role.yaml
			// substring-matches this quoted ARN value inside the flattened `properties` JSON
			// string to create the (NotebookInstance)-[:HAS_ROLE]->(Role) edge.
			"RoleArn": aws.ToString(detail.RoleArn),
		},
	}
}
