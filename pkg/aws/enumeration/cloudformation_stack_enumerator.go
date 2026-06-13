package enumeration

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfntypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// CloudFormationStackEnumerator enumerates CloudFormation stacks using the native
// CloudFormation SDK. Stacks have no resource policy; they are emitted so the
// resource_service_role enricher can link a stack to the IAM role it RUNS AS
// (Stack.RoleARN) via a (Stack)-[:HAS_ROLE]->(Role) edge, which the
// cloudformation_changeset privesc method re-points its CAN_PRIVESC edge at.
type CloudFormationStackEnumerator struct {
	plugin.AWSCommonRecon
	provider   *AWSConfigProvider
	skipReport *SkipReport
}

// NewCloudFormationStackEnumerator creates a CloudFormationStackEnumerator that uses the native CloudFormation SDK.
func NewCloudFormationStackEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider, skipReport *SkipReport) *CloudFormationStackEnumerator {
	return &CloudFormationStackEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
		skipReport:     skipReport,
	}
}

// ResourceType returns the CloudControl type string for CloudFormation stacks.
func (l *CloudFormationStackEnumerator) ResourceType() string {
	return "AWS::CloudFormation::Stack"
}

// EnumerateAll enumerates all CloudFormation stacks owned by the account across configured regions.
func (l *CloudFormationStackEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(l.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	accountID, err := l.provider.GetAccountID(l.Regions[0])
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	actor := ratelimit.NewCrossRegionActor(l.Concurrency)
	return actor.ActInRegions(l.Regions, func(region string) error {
		return l.listStacksInRegion(region, accountID, out)
	})
}

func (l *CloudFormationStackEnumerator) listStacksInRegion(region, accountID string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := l.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create CloudFormation client for %s: %w", region, err)
	}
	client := cloudformation.NewFromConfig(*cfg)

	paginator := cloudformation.NewDescribeStacksPaginator(client, &cloudformation.DescribeStacksInput{})
	var skipped []SkippedOp
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if op := ClassifySkippable(err, "cloudformation", "DescribeStacks", region); op != nil {
				skipped = append(skipped, *op)
				break
			}
			return fmt.Errorf("describe stacks in %s: %w", region, err)
		}
		for _, stack := range page.Stacks {
			out.Send(buildStackResource(stack, accountID, region))
		}
	}

	l.skipReport.RecordBatch(skipped)
	return nil
}

func buildStackResource(stack cfntypes.Stack, accountID, region string) output.AWSResource {
	stackName := aws.ToString(stack.StackName)

	// StackId is a full ARN; fall back to a synthesized ARN if absent (DescribeStacks
	// always returns StackId, but guard against a nil so the node still keys cleanly).
	arn := aws.ToString(stack.StackId)
	if arn == "" {
		arn = fmt.Sprintf("arn:aws:cloudformation:%s:%s:stack/%s", region, accountID, stackName)
	}

	return output.AWSResource{
		ResourceType: "AWS::CloudFormation::Stack",
		ResourceID:   stackName,
		ARN:          arn,
		AccountRef:   accountID,
		Region:       region,
		DisplayName:  stackName,
		Properties: map[string]any{
			"StackName": stackName,
			// RoleARN is the stack's service role; resource_service_role.yaml substring-
			// matches this quoted ARN value inside the flattened `properties` JSON string
			// to create the (Stack)-[:HAS_ROLE]->(Role) edge.
			"RoleARN":     aws.ToString(stack.RoleARN),
			"StackStatus": string(stack.StackStatus),
		},
	}
}
