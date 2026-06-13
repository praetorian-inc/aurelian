package enumeration

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	gluetypes "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// GlueJobEnumerator enumerates Glue jobs using the native Glue SDK. Jobs have no
// resource policy; they are emitted so the resource_service_role enricher can link a
// job to the IAM role it RUNS AS (Job.Role) via a (Job)-[:HAS_ROLE]->(Role) edge,
// which the glue privesc methods re-point their CAN_PRIVESC edge at.
//
// GetJobs returns full job definitions (including Role) directly, so no per-job
// describe is needed. Job.Role can be a role NAME rather than an ARN; only the ARN
// form substring-matches a role node (fail-closed, documented in resource_service_role.yaml).
type GlueJobEnumerator struct {
	plugin.AWSCommonRecon
	provider   *AWSConfigProvider
	skipReport *SkipReport
}

// NewGlueJobEnumerator creates a GlueJobEnumerator that uses the native Glue SDK.
func NewGlueJobEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider, skipReport *SkipReport) *GlueJobEnumerator {
	return &GlueJobEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
		skipReport:     skipReport,
	}
}

// ResourceType returns the CloudControl type string for Glue jobs.
func (l *GlueJobEnumerator) ResourceType() string {
	return "AWS::Glue::Job"
}

// EnumerateAll enumerates all Glue jobs owned by the account across configured regions.
func (l *GlueJobEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(l.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	accountID, err := l.provider.GetAccountID(l.Regions[0])
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	actor := ratelimit.NewCrossRegionActor(l.Concurrency)
	return actor.ActInRegions(l.Regions, func(region string) error {
		return l.listJobsInRegion(region, accountID, out)
	})
}

func (l *GlueJobEnumerator) listJobsInRegion(region, accountID string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := l.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create Glue client for %s: %w", region, err)
	}
	client := glue.NewFromConfig(*cfg)

	paginator := glue.NewGetJobsPaginator(client, &glue.GetJobsInput{})
	var skipped []SkippedOp
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if op := ClassifySkippable(err, "glue", "GetJobs", region); op != nil {
				skipped = append(skipped, *op)
				break
			}
			return fmt.Errorf("get jobs in %s: %w", region, err)
		}
		for _, job := range page.Jobs {
			out.Send(buildGlueJobResource(job, accountID, region))
		}
	}

	l.skipReport.RecordBatch(skipped)
	return nil
}

func buildGlueJobResource(job gluetypes.Job, accountID, region string) output.AWSResource {
	name := aws.ToString(job.Name)

	// Glue jobs carry no ARN field; synthesize the standard Glue job ARN so the node keys cleanly.
	arn := fmt.Sprintf("arn:aws:glue:%s:%s:job/%s", region, accountID, name)

	return output.AWSResource{
		ResourceType: "AWS::Glue::Job",
		ResourceID:   name,
		ARN:          arn,
		AccountRef:   accountID,
		Region:       region,
		DisplayName:  name,
		Properties: map[string]any{
			"Name": name,
			// Role is the role the job assumes; resource_service_role.yaml substring-matches
			// this quoted value inside the flattened `properties` JSON string to create the
			// (Job)-[:HAS_ROLE]->(Role) edge. Only the ARN form matches (a role NAME is
			// left unlinked — fail-closed).
			"Role": aws.ToString(job.Role),
		},
	}
}
