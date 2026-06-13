package enumeration

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/batch"
	batchtypes "github.com/aws/aws-sdk-go-v2/service/batch/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// BatchJobDefinitionEnumerator enumerates ACTIVE AWS Batch job definitions using the
// native Batch SDK. Job definitions have no resource policy; they are emitted so the
// resource_service_role enricher can link a job definition to the IAM role its
// containers RUN AS (ContainerProperties.JobRoleArn / ExecutionRoleArn) via a
// (JobDefinition)-[:HAS_ROLE]->(Role) edge, which the batch_submit_job privesc method
// re-points its CAN_PRIVESC edge at.
type BatchJobDefinitionEnumerator struct {
	plugin.AWSCommonRecon
	provider   *AWSConfigProvider
	skipReport *SkipReport
}

// NewBatchJobDefinitionEnumerator creates a BatchJobDefinitionEnumerator that uses the native Batch SDK.
func NewBatchJobDefinitionEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider, skipReport *SkipReport) *BatchJobDefinitionEnumerator {
	return &BatchJobDefinitionEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
		skipReport:     skipReport,
	}
}

// ResourceType returns the CloudControl type string for Batch job definitions.
func (l *BatchJobDefinitionEnumerator) ResourceType() string {
	return "AWS::Batch::JobDefinition"
}

// EnumerateAll enumerates all ACTIVE Batch job definitions owned by the account across configured regions.
func (l *BatchJobDefinitionEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(l.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	accountID, err := l.provider.GetAccountID(l.Regions[0])
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	actor := ratelimit.NewCrossRegionActor(l.Concurrency)
	return actor.ActInRegions(l.Regions, func(region string) error {
		return l.listJobDefinitionsInRegion(region, accountID, out)
	})
}

func (l *BatchJobDefinitionEnumerator) listJobDefinitionsInRegion(region, accountID string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := l.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create Batch client for %s: %w", region, err)
	}
	client := batch.NewFromConfig(*cfg)

	// Only ACTIVE revisions are submittable, so a deregistered definition cannot be a
	// SubmitJob target — filter to ACTIVE at the API.
	active := "ACTIVE"
	paginator := batch.NewDescribeJobDefinitionsPaginator(client, &batch.DescribeJobDefinitionsInput{Status: &active})
	var skipped []SkippedOp
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if op := ClassifySkippable(err, "batch", "DescribeJobDefinitions", region); op != nil {
				skipped = append(skipped, *op)
				break
			}
			return fmt.Errorf("describe job definitions in %s: %w", region, err)
		}
		for _, jd := range page.JobDefinitions {
			out.Send(buildJobDefinitionResource(jd, accountID, region))
		}
	}

	l.skipReport.RecordBatch(skipped)
	return nil
}

func buildJobDefinitionResource(jd batchtypes.JobDefinition, accountID, region string) output.AWSResource {
	name := aws.ToString(jd.JobDefinitionName)

	// JobDefinitionArn is a full ARN; fall back to a synthesized ARN if absent so the
	// node still keys cleanly (DescribeJobDefinitions always returns the ARN).
	arn := aws.ToString(jd.JobDefinitionArn)
	if arn == "" {
		arn = fmt.Sprintf("arn:aws:batch:%s:%s:job-definition/%s", region, accountID, name)
	}

	// Both role refs live on ContainerProperties: JobRoleArn (the role the job's
	// containers assume — the SubmitJob escalation target) and ExecutionRoleArn (the
	// role the agent uses to pull images / write logs). Capture both so the
	// resource_service_role enricher can substring-match whichever is privileged.
	var jobRoleArn, executionRoleArn string
	if jd.ContainerProperties != nil {
		jobRoleArn = aws.ToString(jd.ContainerProperties.JobRoleArn)
		executionRoleArn = aws.ToString(jd.ContainerProperties.ExecutionRoleArn)
	}

	return output.AWSResource{
		ResourceType: "AWS::Batch::JobDefinition",
		ResourceID:   name,
		ARN:          arn,
		AccountRef:   accountID,
		Region:       region,
		DisplayName:  name,
		Properties: map[string]any{
			"JobDefinitionName": name,
			"Status":            aws.ToString(jd.Status),
			// JobRoleArn / ExecutionRoleArn are substring-matched (quoted) inside the
			// flattened `properties` JSON string by resource_service_role.yaml to create
			// the (JobDefinition)-[:HAS_ROLE]->(Role) edge.
			"JobRoleArn":       jobRoleArn,
			"ExecutionRoleArn": executionRoleArn,
		},
	}
}
