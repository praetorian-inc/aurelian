package enumeration

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// EC2InstanceEnumerator enumerates EC2 instances using the native EC2 SDK.
// Instances have no resource policy; they are emitted so instance-scoped privesc
// actions (e.g. ec2:ReplaceIamInstanceProfileAssociation) can resolve against a
// concrete instance ARN in the evaluator's resource store.
type EC2InstanceEnumerator struct {
	plugin.AWSCommonRecon
	provider   *AWSConfigProvider
	skipReport *SkipReport
}

// NewEC2InstanceEnumerator creates an EC2InstanceEnumerator that uses the native EC2 SDK.
func NewEC2InstanceEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider, skipReport *SkipReport) *EC2InstanceEnumerator {
	return &EC2InstanceEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
		skipReport:     skipReport,
	}
}

// ResourceType returns the CloudControl type string for EC2 instances.
func (l *EC2InstanceEnumerator) ResourceType() string {
	return "AWS::EC2::Instance"
}

// EnumerateAll enumerates all EC2 instances owned by the account across configured regions.
func (l *EC2InstanceEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(l.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	accountID, err := l.provider.GetAccountID(l.Regions[0])
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	actor := ratelimit.NewCrossRegionActor(l.Concurrency)
	return actor.ActInRegions(l.Regions, func(region string) error {
		return l.listInstancesInRegion(region, accountID, out)
	})
}

func (l *EC2InstanceEnumerator) listInstancesInRegion(region, accountID string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := l.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create EC2 client for %s: %w", region, err)
	}
	client := ec2.NewFromConfig(*cfg)

	paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
	var skipped []SkippedOp
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if op := ClassifySkippable(err, "ec2", "DescribeInstances", region); op != nil {
				skipped = append(skipped, *op)
				break
			}
			return fmt.Errorf("describe instances in %s: %w", region, err)
		}
		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				out.Send(buildInstanceResource(instance, accountID, region))
			}
		}
	}

	l.skipReport.RecordBatch(skipped)
	return nil
}

func buildInstanceResource(instance ec2types.Instance, accountID, region string) output.AWSResource {
	instanceID := aws.ToString(instance.InstanceId)

	var instanceProfileARN string
	if instance.IamInstanceProfile != nil {
		instanceProfileARN = aws.ToString(instance.IamInstanceProfile.Arn)
	}

	var state string
	if instance.State != nil {
		state = string(instance.State.Name)
	}

	return output.AWSResource{
		ResourceType: "AWS::EC2::Instance",
		ResourceID:   instanceID,
		ARN:          fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", region, accountID, instanceID),
		AccountRef:   accountID,
		Region:       region,
		DisplayName:  instanceID,
		Properties: map[string]any{
			"InstanceId":         instanceID,
			"State":              state,
			"IamInstanceProfile": instanceProfileARN,
		},
	}
}
