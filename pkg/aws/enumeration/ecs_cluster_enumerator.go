package enumeration

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// describeClustersBatchSize is the DescribeClusters cluster-ARN limit per call (AWS caps it at 100).
const describeClustersBatchSize = 100

// ECSClusterEnumerator enumerates ECS clusters using the native ECS SDK. Clusters carry
// NO IAM role, so unlike the task-definition enumerator they emit no HAS_ROLE edge. They
// are emitted purely so the cluster node EXISTS as an IAM-evaluation candidate resource:
// an attacker policy that scopes ecs:ExecuteCommand to a cluster ARN
// (arn:aws:ecs:*:<acct>:cluster/<name>) only produces a base ECS_EXECUTECOMMAND edge when
// the IAM evaluator can match that grant against a concrete cluster resource. The privesc
// target is reached via the task definition's existing HAS_ROLE, not via the cluster.
//
// ListClusters returns only ARNs, so each batch is described via DescribeClusters to obtain
// the cluster name and status.
type ECSClusterEnumerator struct {
	plugin.AWSCommonRecon
	provider   *AWSConfigProvider
	skipReport *SkipReport
}

// NewECSClusterEnumerator creates an ECSClusterEnumerator that uses the native ECS SDK.
func NewECSClusterEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider, skipReport *SkipReport) *ECSClusterEnumerator {
	return &ECSClusterEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
		skipReport:     skipReport,
	}
}

// ResourceType returns the CloudControl type string for ECS clusters.
func (l *ECSClusterEnumerator) ResourceType() string {
	return "AWS::ECS::Cluster"
}

// EnumerateAll enumerates all ECS clusters owned by the account across configured regions.
func (l *ECSClusterEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(l.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	accountID, err := l.provider.GetAccountID(l.Regions[0])
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	actor := ratelimit.NewCrossRegionActor(l.Concurrency)
	return actor.ActInRegions(l.Regions, func(region string) error {
		return l.listClustersInRegion(region, accountID, out)
	})
}

func (l *ECSClusterEnumerator) listClustersInRegion(region, accountID string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := l.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create ECS client for %s: %w", region, err)
	}
	client := ecs.NewFromConfig(*cfg)

	paginator := ecs.NewListClustersPaginator(client, &ecs.ListClustersInput{})
	var skipped []SkippedOp
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if op := ClassifySkippable(err, "ecs", "ListClusters", region); op != nil {
				skipped = append(skipped, *op)
				break
			}
			return fmt.Errorf("list clusters in %s: %w", region, err)
		}
		// ListClusters returns only ARNs; describe them in batches to get the name/status.
		for start := 0; start < len(page.ClusterArns); start += describeClustersBatchSize {
			end := start + describeClustersBatchSize
			if end > len(page.ClusterArns) {
				end = len(page.ClusterArns)
			}
			detail, err := client.DescribeClusters(context.Background(), &ecs.DescribeClustersInput{
				Clusters: page.ClusterArns[start:end],
			})
			if err != nil {
				if op := ClassifySkippable(err, "ecs", "DescribeClusters", region); op != nil {
					skipped = append(skipped, *op)
					continue
				}
				return fmt.Errorf("describe clusters in %s: %w", region, err)
			}
			for i := range detail.Clusters {
				out.Send(buildECSClusterResource(&detail.Clusters[i], accountID, region))
			}
		}
	}

	l.skipReport.RecordBatch(skipped)
	return nil
}

func buildECSClusterResource(c *ecstypes.Cluster, accountID, region string) output.AWSResource {
	arn := aws.ToString(c.ClusterArn)

	// ClusterName is the escalation-scope key (the attacker policy scopes ExecuteCommand to
	// cluster/<name>). Fall back to the name embedded in the ARN if DescribeClusters omits it.
	name := aws.ToString(c.ClusterName)
	if name == "" {
		name = clusterNameFromARN(arn)
	}

	// Defensive: if the ARN is absent (it is the list key, so this should not happen),
	// synthesize one keyed on the name so the node still keys cleanly.
	if arn == "" && name != "" {
		arn = fmt.Sprintf("arn:aws:ecs:%s:%s:cluster/%s", region, accountID, name)
	}

	return output.AWSResource{
		ResourceType: "AWS::ECS::Cluster",
		ResourceID:   name,
		ARN:          arn,
		AccountRef:   accountID,
		Region:       region,
		DisplayName:  name,
		Properties: map[string]any{
			"ClusterName": name,
			"Status":      aws.ToString(c.Status),
		},
	}
}

// clusterNameFromARN extracts the cluster name from an ECS cluster ARN
// (arn:aws:ecs:<region>:<acct>:cluster/<name>), returning "" if the ARN has no cluster path.
func clusterNameFromARN(arn string) string {
	_, name, found := strings.Cut(arn, "cluster/")
	if !found {
		return ""
	}
	return name
}
