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

// CloudFormationStackSetEnumerator enumerates CloudFormation stack sets using the native
// CloudFormation SDK. Stack sets have no resource policy; they are emitted so the
// resource_service_role enricher can link a stack set to the IAM role it RUNS AS
// (AdministrationRoleARN) via a (StackSet)-[:HAS_ROLE]->(Role) edge, which the
// cloudformation stackset privesc methods re-point their CAN_PRIVESC edge at.
//
// ListStackSets summaries do NOT include the administration role, so each is described
// per-name via DescribeStackSet.
type CloudFormationStackSetEnumerator struct {
	plugin.AWSCommonRecon
	provider   *AWSConfigProvider
	skipReport *SkipReport
}

// NewCloudFormationStackSetEnumerator creates a CloudFormationStackSetEnumerator that uses the native CloudFormation SDK.
func NewCloudFormationStackSetEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider, skipReport *SkipReport) *CloudFormationStackSetEnumerator {
	return &CloudFormationStackSetEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
		skipReport:     skipReport,
	}
}

// ResourceType returns the CloudControl type string for CloudFormation stack sets.
func (l *CloudFormationStackSetEnumerator) ResourceType() string {
	return "AWS::CloudFormation::StackSet"
}

// EnumerateAll enumerates all CloudFormation stack sets owned by the account across configured regions.
func (l *CloudFormationStackSetEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(l.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	accountID, err := l.provider.GetAccountID(l.Regions[0])
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	actor := ratelimit.NewCrossRegionActor(l.Concurrency)
	return actor.ActInRegions(l.Regions, func(region string) error {
		return l.listStackSetsInRegion(region, accountID, out)
	})
}

func (l *CloudFormationStackSetEnumerator) listStackSetsInRegion(region, accountID string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := l.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create CloudFormation client for %s: %w", region, err)
	}
	client := cloudformation.NewFromConfig(*cfg)

	paginator := cloudformation.NewListStackSetsPaginator(client, &cloudformation.ListStackSetsInput{})
	var skipped []SkippedOp
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if op := ClassifySkippable(err, "cloudformation", "ListStackSets", region); op != nil {
				skipped = append(skipped, *op)
				break
			}
			return fmt.Errorf("list stack sets in %s: %w", region, err)
		}
		for _, summary := range page.Summaries {
			name := aws.ToString(summary.StackSetName)
			if name == "" {
				continue
			}
			// The summary carries no role; describe per-name.
			detail, err := client.DescribeStackSet(context.Background(), &cloudformation.DescribeStackSetInput{
				StackSetName: summary.StackSetName,
			})
			if err != nil {
				if op := ClassifySkippable(err, "cloudformation", "DescribeStackSet", region); op != nil {
					skipped = append(skipped, *op)
					continue
				}
				return fmt.Errorf("describe stack set %s in %s: %w", name, region, err)
			}
			if detail.StackSet == nil {
				continue
			}
			out.Send(buildStackSetResource(detail.StackSet, accountID, region))
		}
	}

	l.skipReport.RecordBatch(skipped)
	return nil
}

func buildStackSetResource(stackSet *cfntypes.StackSet, accountID, region string) output.AWSResource {
	name := aws.ToString(stackSet.StackSetName)

	// StackSetARN is the full ARN; fall back to a synthesized ARN if absent so the node
	// still keys cleanly.
	arn := aws.ToString(stackSet.StackSetARN)
	if arn == "" {
		arn = fmt.Sprintf("arn:aws:cloudformation:%s:%s:stackset/%s", region, accountID, name)
	}

	return output.AWSResource{
		ResourceType: "AWS::CloudFormation::StackSet",
		ResourceID:   name,
		ARN:          arn,
		AccountRef:   accountID,
		Region:       region,
		DisplayName:  name,
		Properties: map[string]any{
			"StackSetName": name,
			// AdministrationRoleARN is the role the stack set's operations assume;
			// resource_service_role.yaml substring-matches this quoted ARN value inside the
			// flattened `properties` JSON string to create the (StackSet)-[:HAS_ROLE]->(Role) edge.
			"AdministrationRoleARN": aws.ToString(stackSet.AdministrationRoleARN),
			// ExecutionRoleName is a role NAME, not an ARN, so it will NOT substring-match a
			// role ARN and is left unlinked (fail-closed). Captured for completeness.
			"ExecutionRoleName": aws.ToString(stackSet.ExecutionRoleName),
		},
	}
}
