package enumeration

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	bedrockcc "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// BedrockCodeInterpreterEnumerator enumerates Bedrock AgentCore code interpreters using
// the native bedrock-agentcore-control SDK. Code interpreters have no resource policy;
// they are emitted so the resource_service_role enricher can link an interpreter to the
// IAM role it RUNS AS (GetCodeInterpreter.ExecutionRoleArn) via a
// (CodeInterpreter)-[:HAS_ROLE]->(Role) edge, which the bedrock_access_code_interpreter
// privesc method re-points its CAN_PRIVESC edge at.
//
// ListCodeInterpreters summaries do NOT include the execution role, so each interpreter
// is enumerated via ListCodeInterpreters then described per-id via GetCodeInterpreter.
type BedrockCodeInterpreterEnumerator struct {
	plugin.AWSCommonRecon
	provider   *AWSConfigProvider
	skipReport *SkipReport
}

// NewBedrockCodeInterpreterEnumerator creates a BedrockCodeInterpreterEnumerator that uses the native bedrock-agentcore-control SDK.
func NewBedrockCodeInterpreterEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider, skipReport *SkipReport) *BedrockCodeInterpreterEnumerator {
	return &BedrockCodeInterpreterEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
		skipReport:     skipReport,
	}
}

// ResourceType returns the CloudControl type string for Bedrock AgentCore code interpreters.
func (l *BedrockCodeInterpreterEnumerator) ResourceType() string {
	return "AWS::BedrockAgentCore::CodeInterpreter"
}

// EnumerateAll enumerates all code interpreters owned by the account across configured regions.
func (l *BedrockCodeInterpreterEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(l.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	accountID, err := l.provider.GetAccountID(l.Regions[0])
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	actor := ratelimit.NewCrossRegionActor(l.Concurrency)
	return actor.ActInRegions(l.Regions, func(region string) error {
		return l.listCodeInterpretersInRegion(region, accountID, out)
	})
}

func (l *BedrockCodeInterpreterEnumerator) listCodeInterpretersInRegion(region, accountID string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := l.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create Bedrock AgentCore client for %s: %w", region, err)
	}
	client := bedrockcc.NewFromConfig(*cfg)

	paginator := bedrockcc.NewListCodeInterpretersPaginator(client, &bedrockcc.ListCodeInterpretersInput{})
	var skipped []SkippedOp
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if op := ClassifySkippable(err, "bedrock-agentcore", "ListCodeInterpreters", region); op != nil {
				skipped = append(skipped, *op)
				break
			}
			return fmt.Errorf("list code interpreters in %s: %w", region, err)
		}
		for _, summary := range page.CodeInterpreterSummaries {
			id := aws.ToString(summary.CodeInterpreterId)
			if id == "" {
				continue
			}
			// The summary carries the ARN but NOT the execution role; describe per-id.
			detail, err := client.GetCodeInterpreter(context.Background(), &bedrockcc.GetCodeInterpreterInput{
				CodeInterpreterId: summary.CodeInterpreterId,
			})
			if err != nil {
				if op := ClassifySkippable(err, "bedrock-agentcore", "GetCodeInterpreter", region); op != nil {
					skipped = append(skipped, *op)
					continue
				}
				return fmt.Errorf("get code interpreter %s in %s: %w", id, region, err)
			}
			out.Send(buildCodeInterpreterResource(detail, accountID, region))
		}
	}

	l.skipReport.RecordBatch(skipped)
	return nil
}

func buildCodeInterpreterResource(detail *bedrockcc.GetCodeInterpreterOutput, accountID, region string) output.AWSResource {
	id := aws.ToString(detail.CodeInterpreterId)
	name := aws.ToString(detail.Name)

	// CodeInterpreterArn is a full ARN; fall back to a synthesized ARN if absent so the
	// node still keys cleanly.
	arn := aws.ToString(detail.CodeInterpreterArn)
	if arn == "" {
		arn = fmt.Sprintf("arn:aws:bedrock-agentcore:%s:%s:code-interpreter/%s", region, accountID, id)
	}

	return output.AWSResource{
		ResourceType: "AWS::BedrockAgentCore::CodeInterpreter",
		ResourceID:   id,
		ARN:          arn,
		AccountRef:   accountID,
		Region:       region,
		DisplayName:  name,
		Properties: map[string]any{
			"CodeInterpreterId": id,
			"Name":              name,
			"Status":            string(detail.Status),
			// ExecutionRoleArn is the role the interpreter sessions run as;
			// resource_service_role.yaml substring-matches this quoted ARN value inside the
			// flattened `properties` JSON string to create the HAS_ROLE edge.
			"ExecutionRoleArn": aws.ToString(detail.ExecutionRoleArn),
		},
	}
}
