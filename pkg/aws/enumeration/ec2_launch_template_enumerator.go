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

// EC2LaunchTemplateEnumerator enumerates EC2 launch templates using the native EC2 SDK.
// Launch templates have no resource policy; they are emitted so the existing-template
// privesc method (ec2_launch_template_version) can re-point its CAN_PRIVESC edge at the
// IAM role new instances RUN AS. The launch template references that role indirectly via
// an IAM instance profile (IamInstanceProfile in the template's default version), so the
// emitted resource carries the instance-profile reference and resolves to the role the
// SAME way an EC2 instance does: an instance-profile -> role HAS_ROLE enricher matches it
// against the role's InstanceProfileList.
//
// DescribeLaunchTemplates summaries do NOT include the template data, so each template's
// default version is described per-template via DescribeLaunchTemplateVersions.
type EC2LaunchTemplateEnumerator struct {
	plugin.AWSCommonRecon
	provider   *AWSConfigProvider
	skipReport *SkipReport
}

// NewEC2LaunchTemplateEnumerator creates an EC2LaunchTemplateEnumerator that uses the native EC2 SDK.
func NewEC2LaunchTemplateEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider, skipReport *SkipReport) *EC2LaunchTemplateEnumerator {
	return &EC2LaunchTemplateEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
		skipReport:     skipReport,
	}
}

// ResourceType returns the CloudControl type string for EC2 launch templates.
func (l *EC2LaunchTemplateEnumerator) ResourceType() string {
	return "AWS::EC2::LaunchTemplate"
}

// EnumerateAll enumerates all EC2 launch templates owned by the account across configured regions.
func (l *EC2LaunchTemplateEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(l.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	accountID, err := l.provider.GetAccountID(l.Regions[0])
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	actor := ratelimit.NewCrossRegionActor(l.Concurrency)
	return actor.ActInRegions(l.Regions, func(region string) error {
		return l.listLaunchTemplatesInRegion(region, accountID, out)
	})
}

func (l *EC2LaunchTemplateEnumerator) listLaunchTemplatesInRegion(region, accountID string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := l.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create EC2 client for %s: %w", region, err)
	}
	client := ec2.NewFromConfig(*cfg)

	paginator := ec2.NewDescribeLaunchTemplatesPaginator(client, &ec2.DescribeLaunchTemplatesInput{})
	var skipped []SkippedOp
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if op := ClassifySkippable(err, "ec2", "DescribeLaunchTemplates", region); op != nil {
				skipped = append(skipped, *op)
				break
			}
			return fmt.Errorf("describe launch templates in %s: %w", region, err)
		}
		for _, tmpl := range page.LaunchTemplates {
			id := aws.ToString(tmpl.LaunchTemplateId)
			if id == "" {
				continue
			}
			// The template summary carries no template data; describe its default version
			// to read the IamInstanceProfile new instances launch with.
			profileRef, err := l.defaultVersionInstanceProfile(client, &tmpl, region, &skipped)
			if err != nil {
				return err
			}
			out.Send(buildLaunchTemplateResource(tmpl, profileRef, accountID, region))
		}
	}

	l.skipReport.RecordBatch(skipped)
	return nil
}

// defaultVersionInstanceProfile returns the instance-profile reference (ARN or name) the
// launch template's default version binds, or "" when the version omits one. A skipped
// describe is recorded and treated as "no profile" so one inaccessible template does not
// fail the whole region.
func (l *EC2LaunchTemplateEnumerator) defaultVersionInstanceProfile(client *ec2.Client, tmpl *ec2types.LaunchTemplate, region string, skipped *[]SkippedOp) (string, error) {
	out, err := client.DescribeLaunchTemplateVersions(context.Background(), &ec2.DescribeLaunchTemplateVersionsInput{
		LaunchTemplateId: tmpl.LaunchTemplateId,
		Versions:         []string{"$Default"},
	})
	if err != nil {
		if op := ClassifySkippable(err, "ec2", "DescribeLaunchTemplateVersions", region); op != nil {
			*skipped = append(*skipped, *op)
			return "", nil
		}
		return "", fmt.Errorf("describe launch template versions for %s in %s: %w", aws.ToString(tmpl.LaunchTemplateId), region, err)
	}
	for _, version := range out.LaunchTemplateVersions {
		if version.LaunchTemplateData == nil || version.LaunchTemplateData.IamInstanceProfile == nil {
			continue
		}
		profile := version.LaunchTemplateData.IamInstanceProfile
		if arn := aws.ToString(profile.Arn); arn != "" {
			return arn, nil
		}
		return aws.ToString(profile.Name), nil
	}
	return "", nil
}

func buildLaunchTemplateResource(tmpl ec2types.LaunchTemplate, instanceProfileRef, accountID, region string) output.AWSResource {
	id := aws.ToString(tmpl.LaunchTemplateId)
	name := aws.ToString(tmpl.LaunchTemplateName)

	return output.AWSResource{
		ResourceType: "AWS::EC2::LaunchTemplate",
		ResourceID:   id,
		ARN:          fmt.Sprintf("arn:aws:ec2:%s:%s:launch-template/%s", region, accountID, id),
		AccountRef:   accountID,
		Region:       region,
		DisplayName:  name,
		Properties: map[string]any{
			"LaunchTemplateId":   id,
			"LaunchTemplateName": name,
			// IamInstanceProfile is the instance profile new instances launch with (ARN or
			// name). NodeFromAWSResource promotes it to a top-level node property and
			// set_launch_template_role.yaml matches it against the role's InstanceProfileList
			// to create the (LaunchTemplate)-[:HAS_ROLE]->(Role) edge.
			"IamInstanceProfile": instanceProfileRef,
		},
	}
}
