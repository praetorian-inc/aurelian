package enumeration

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// ECSTaskDefinitionEnumerator enumerates ACTIVE ECS task definitions using the native
// ECS SDK. Task definitions have no resource policy; they are emitted so the
// resource_service_role enricher can link a task definition to the IAM roles its tasks
// RUN AS (TaskRoleArn / ExecutionRoleArn) via a (TaskDefinition)-[:HAS_ROLE]->(Role)
// edge, which the ecs privesc methods re-point their CAN_PRIVESC edge at.
//
// ListTaskDefinitions returns only ARNs, so each is described via DescribeTaskDefinition
// to obtain the task and execution roles.
type ECSTaskDefinitionEnumerator struct {
	plugin.AWSCommonRecon
	provider   *AWSConfigProvider
	skipReport *SkipReport
}

// NewECSTaskDefinitionEnumerator creates an ECSTaskDefinitionEnumerator that uses the native ECS SDK.
func NewECSTaskDefinitionEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider, skipReport *SkipReport) *ECSTaskDefinitionEnumerator {
	return &ECSTaskDefinitionEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
		skipReport:     skipReport,
	}
}

// ResourceType returns the CloudControl type string for ECS task definitions.
func (l *ECSTaskDefinitionEnumerator) ResourceType() string {
	return "AWS::ECS::TaskDefinition"
}

// EnumerateAll enumerates all ACTIVE ECS task definitions owned by the account across configured regions.
func (l *ECSTaskDefinitionEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(l.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	accountID, err := l.provider.GetAccountID(l.Regions[0])
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	actor := ratelimit.NewCrossRegionActor(l.Concurrency)
	return actor.ActInRegions(l.Regions, func(region string) error {
		return l.listTaskDefinitionsInRegion(region, accountID, out)
	})
}

func (l *ECSTaskDefinitionEnumerator) EnumerateByARN(arn string, out *pipeline.P[output.AWSResource]) error {
	parsed, err := awsarn.Parse(arn)
	if err != nil {
		return fmt.Errorf("parse ARN %q: %w", arn, err)
	}
	if _, ok := strings.CutPrefix(parsed.Resource, "task-definition/"); !ok {
		return fmt.Errorf("invalid ECS task definition ARN resource: %q", parsed.Resource)
	}
	if parsed.Region == "" {
		return fmt.Errorf("ECS task definition ARN missing region: %q", arn)
	}

	cfg, err := l.provider.GetAWSConfig(parsed.Region)
	if err != nil {
		return fmt.Errorf("create ECS client for %s: %w", parsed.Region, err)
	}
	result, err := ecs.NewFromConfig(*cfg).DescribeTaskDefinition(context.Background(), &ecs.DescribeTaskDefinitionInput{
		TaskDefinition: aws.String(arn),
	})
	if err != nil {
		if op := ClassifySkippable(err, "ecs", "DescribeTaskDefinition", parsed.Region); op != nil {
			l.skipReport.Record(*op)
			return nil
		}
		return fmt.Errorf("describe task definition %s: %w", arn, err)
	}
	if result.TaskDefinition == nil {
		return fmt.Errorf("describe task definition %s returned no task definition", arn)
	}

	out.Send(buildECSTaskDefinitionResource(result.TaskDefinition, parsed.AccountID, parsed.Region))
	return nil
}

func (l *ECSTaskDefinitionEnumerator) listTaskDefinitionsInRegion(region, accountID string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := l.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create ECS client for %s: %w", region, err)
	}
	client := ecs.NewFromConfig(*cfg)

	// Only ACTIVE task definitions are runnable, so a deregistered revision cannot be a
	// RunTask target — filter to ACTIVE at the API.
	paginator := ecs.NewListTaskDefinitionsPaginator(client, &ecs.ListTaskDefinitionsInput{
		Status: ecstypes.TaskDefinitionStatusActive,
	})
	var skipped []SkippedOp
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if op := ClassifySkippable(err, "ecs", "ListTaskDefinitions", region); op != nil {
				skipped = append(skipped, *op)
				break
			}
			return fmt.Errorf("list task definitions in %s: %w", region, err)
		}
		for _, arn := range page.TaskDefinitionArns {
			detail, err := client.DescribeTaskDefinition(context.Background(), &ecs.DescribeTaskDefinitionInput{
				TaskDefinition: aws.String(arn),
			})
			if err != nil {
				if op := ClassifySkippable(err, "ecs", "DescribeTaskDefinition", region); op != nil {
					skipped = append(skipped, *op)
					continue
				}
				return fmt.Errorf("describe task definition %s in %s: %w", arn, region, err)
			}
			if detail.TaskDefinition == nil {
				continue
			}
			out.Send(buildECSTaskDefinitionResource(detail.TaskDefinition, accountID, region))
		}
	}

	l.skipReport.RecordBatch(skipped)
	return nil
}

func buildECSTaskDefinitionResource(td *ecstypes.TaskDefinition, accountID, region string) output.AWSResource {
	family := aws.ToString(td.Family)

	// TaskDefinitionArn is the full revision ARN (family:revision); fall back to a
	// synthesized ARN if absent so the node still keys cleanly.
	arn := aws.ToString(td.TaskDefinitionArn)
	if arn == "" {
		arn = fmt.Sprintf("arn:aws:ecs:%s:%s:task-definition/%s", region, accountID, family)
	}

	return output.AWSResource{
		ResourceType: "AWS::ECS::TaskDefinition",
		ResourceID:   family,
		ARN:          arn,
		AccountRef:   accountID,
		Region:       region,
		DisplayName:  family,
		LastModified: td.RegisteredAt,
		Properties: map[string]any{
			"Family": family,
			// TaskRoleArn (the role the task's containers assume — the escalation target) and
			// ExecutionRoleArn (the role the agent uses to pull images / write logs). Both are
			// substring-matched (quoted) inside the flattened `properties` JSON string by
			// resource_service_role.yaml to create the (TaskDefinition)-[:HAS_ROLE]->(Role) edge.
			"TaskRoleArn":      aws.ToString(td.TaskRoleArn),
			"ExecutionRoleArn": aws.ToString(td.ExecutionRoleArn),
		},
	}
}
