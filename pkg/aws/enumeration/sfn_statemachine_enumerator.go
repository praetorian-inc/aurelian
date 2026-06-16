package enumeration

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// SFNStateMachineEnumerator enumerates Step Functions state machines using the native
// Step Functions SDK. State machines have no resource policy; they are emitted so the
// resource_service_role enricher can link a state machine to the IAM role it RUNS AS
// (DescribeStateMachine.RoleArn) via a (StateMachine)-[:HAS_ROLE]->(Role) edge, which
// the stepfunctions privesc methods re-point their CAN_PRIVESC edge at.
//
// ListStateMachines summaries do NOT include the role, so each is described per-ARN via
// DescribeStateMachine.
type SFNStateMachineEnumerator struct {
	plugin.AWSCommonRecon
	provider   *AWSConfigProvider
	skipReport *SkipReport
}

// NewSFNStateMachineEnumerator creates an SFNStateMachineEnumerator that uses the native Step Functions SDK.
func NewSFNStateMachineEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider, skipReport *SkipReport) *SFNStateMachineEnumerator {
	return &SFNStateMachineEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
		skipReport:     skipReport,
	}
}

// ResourceType returns the CloudControl type string for Step Functions state machines.
func (l *SFNStateMachineEnumerator) ResourceType() string {
	return "AWS::StepFunctions::StateMachine"
}

// EnumerateAll enumerates all Step Functions state machines owned by the account across configured regions.
func (l *SFNStateMachineEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(l.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	accountID, err := l.provider.GetAccountID(l.Regions[0])
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	actor := ratelimit.NewCrossRegionActor(l.Concurrency)
	return actor.ActInRegions(l.Regions, func(region string) error {
		return l.listStateMachinesInRegion(region, accountID, out)
	})
}

func (l *SFNStateMachineEnumerator) listStateMachinesInRegion(region, accountID string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := l.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create Step Functions client for %s: %w", region, err)
	}
	client := sfn.NewFromConfig(*cfg)

	paginator := sfn.NewListStateMachinesPaginator(client, &sfn.ListStateMachinesInput{})
	var skipped []SkippedOp
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if op := ClassifySkippable(err, "stepfunctions", "ListStateMachines", region); op != nil {
				skipped = append(skipped, *op)
				break
			}
			return fmt.Errorf("list state machines in %s: %w", region, err)
		}
		for _, summary := range page.StateMachines {
			arn := aws.ToString(summary.StateMachineArn)
			if arn == "" {
				continue
			}
			// The summary carries the ARN but NOT the role; describe per-ARN.
			detail, err := client.DescribeStateMachine(context.Background(), &sfn.DescribeStateMachineInput{
				StateMachineArn: summary.StateMachineArn,
			})
			if err != nil {
				if op := ClassifySkippable(err, "stepfunctions", "DescribeStateMachine", region); op != nil {
					skipped = append(skipped, *op)
					continue
				}
				return fmt.Errorf("describe state machine %s in %s: %w", arn, region, err)
			}
			out.Send(buildSFNStateMachineResource(detail, accountID, region))
		}
	}

	l.skipReport.RecordBatch(skipped)
	return nil
}

func buildSFNStateMachineResource(detail *sfn.DescribeStateMachineOutput, accountID, region string) output.AWSResource {
	name := aws.ToString(detail.Name)

	// StateMachineArn is the full ARN; fall back to a synthesized ARN if absent so the
	// node still keys cleanly (DescribeStateMachine always returns the ARN).
	arn := aws.ToString(detail.StateMachineArn)
	if arn == "" {
		arn = fmt.Sprintf("arn:aws:states:%s:%s:stateMachine:%s", region, accountID, name)
	}

	return output.AWSResource{
		ResourceType: "AWS::StepFunctions::StateMachine",
		ResourceID:   name,
		ARN:          arn,
		AccountRef:   accountID,
		Region:       region,
		DisplayName:  name,
		Properties: map[string]any{
			"Name": name,
			// RoleArn is the role the state machine's executions assume;
			// resource_service_role.yaml substring-matches this quoted ARN value inside the
			// flattened `properties` JSON string to create the (StateMachine)-[:HAS_ROLE]->(Role) edge.
			"RoleArn": aws.ToString(detail.RoleArn),
		},
	}
}
