package enumeration

import (
	"context"
	"fmt"
	"log/slog"

	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// CodeBuildEnumerator enumerates CodeBuild projects using the native SDK.
// CloudControl does not support LIST for AWS::CodeBuild::Project.
type CodeBuildEnumerator struct {
	plugin.AWSCommonRecon
	provider   *AWSConfigProvider
	skipReport *SkipReport
}

func NewCodeBuildEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider, skipReport *SkipReport) *CodeBuildEnumerator {
	return &CodeBuildEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
		skipReport:     skipReport,
	}
}

func (l *CodeBuildEnumerator) ResourceType() string { return "AWS::CodeBuild::Project" }

func (l *CodeBuildEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(l.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}
	actor := ratelimit.NewCrossRegionActor(l.Concurrency)
	return actor.ActInRegions(l.Regions, func(region string) error {
		return l.listInRegion(region, out)
	})
}

func (l *CodeBuildEnumerator) EnumerateByARN(_ string, _ *pipeline.P[output.AWSResource]) error {
	return errFallbackToCloudControl
}

func (l *CodeBuildEnumerator) listInRegion(region string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := l.provider.GetAWSConfig(region)
	if err != nil {
		return l.skip(region, err)
	}
	client := codebuild.NewFromConfig(*cfg)

	// Step 1: list project names
	var projectNames []string
	listInput := &codebuild.ListProjectsInput{}
	for {
		resp, err := client.ListProjects(context.Background(), listInput)
		if err != nil {
			return l.skip(region, err)
		}
		projectNames = append(projectNames, resp.Projects...)
		if resp.NextToken == nil {
			break
		}
		listInput.NextToken = resp.NextToken
	}

	if len(projectNames) == 0 {
		return nil
	}

	// Step 2: batch get project details (max 100 per call)
	for i := 0; i < len(projectNames); i += 100 {
		end := i + 100
		if end > len(projectNames) {
			end = len(projectNames)
		}
		batch := projectNames[i:end]

		resp, err := client.BatchGetProjects(context.Background(), &codebuild.BatchGetProjectsInput{
			Names: batch,
		})
		if err != nil {
			return l.skip(region, err)
		}

		for _, project := range resp.Projects {
			if project.Arn == nil {
				continue
			}

			parsed, _ := awsarn.Parse(*project.Arn)

			props := make(map[string]any)
			if project.ServiceRole != nil {
				props["ServiceRole"] = *project.ServiceRole
			}
			if project.Name != nil {
				props["Name"] = *project.Name
			}

			r := output.AWSResource{
				ResourceType: "AWS::CodeBuild::Project",
				ResourceID:   *project.Arn,
				ARN:          *project.Arn,
				Region:       region,
				AccountRef:   parsed.AccountID,
				DisplayName:  stringVal(project.Name),
				Properties:   props,
			}
			out.Send(r)
		}
	}

	return nil
}

func (l *CodeBuildEnumerator) skip(region string, err error) error {
	if op := ClassifySkippable(err, "codebuild", "ListProjects", region); op != nil {
		l.skipReport.Record(*op)
		return nil
	}
	slog.Warn("CodeBuild ListProjects failed", "region", region, "error", err)
	return nil
}

func stringVal(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
