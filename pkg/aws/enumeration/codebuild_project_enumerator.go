package enumeration

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	codebuildtypes "github.com/aws/aws-sdk-go-v2/service/codebuild/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// CodeBuildProjectEnumerator enumerates CodeBuild projects using the native CodeBuild
// SDK. Projects have no resource policy; they are emitted so the resource_service_role
// enricher can link a project to the IAM role its builds RUN AS (Project.ServiceRole)
// via a (Project)-[:HAS_ROLE]->(Role) edge, which the codebuild privesc methods
// re-point their CAN_PRIVESC edge at.
//
// ListProjects returns only project names, so each batch of names is described via
// BatchGetProjects (max 100 per call) to obtain the ServiceRole.
type CodeBuildProjectEnumerator struct {
	plugin.AWSCommonRecon
	provider   *AWSConfigProvider
	skipReport *SkipReport
}

// NewCodeBuildProjectEnumerator creates a CodeBuildProjectEnumerator that uses the native CodeBuild SDK.
func NewCodeBuildProjectEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider, skipReport *SkipReport) *CodeBuildProjectEnumerator {
	return &CodeBuildProjectEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
		skipReport:     skipReport,
	}
}

// ResourceType returns the CloudControl type string for CodeBuild projects.
func (l *CodeBuildProjectEnumerator) ResourceType() string {
	return "AWS::CodeBuild::Project"
}

// EnumerateAll enumerates all CodeBuild projects owned by the account across configured regions.
func (l *CodeBuildProjectEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(l.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	accountID, err := l.provider.GetAccountID(l.Regions[0])
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	actor := ratelimit.NewCrossRegionActor(l.Concurrency)
	return actor.ActInRegions(l.Regions, func(region string) error {
		return l.listProjectsInRegion(region, accountID, out)
	})
}

func (l *CodeBuildProjectEnumerator) listProjectsInRegion(region, accountID string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := l.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create CodeBuild client for %s: %w", region, err)
	}
	client := codebuild.NewFromConfig(*cfg)

	paginator := codebuild.NewListProjectsPaginator(client, &codebuild.ListProjectsInput{})
	var skipped []SkippedOp
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if op := ClassifySkippable(err, "codebuild", "ListProjects", region); op != nil {
				skipped = append(skipped, *op)
				break
			}
			return fmt.Errorf("list projects in %s: %w", region, err)
		}
		// BatchGetProjects accepts at most 100 names per call.
		for _, batch := range chunkStrings(page.Projects, 100) {
			detail, err := client.BatchGetProjects(context.Background(), &codebuild.BatchGetProjectsInput{Names: batch})
			if err != nil {
				if op := ClassifySkippable(err, "codebuild", "BatchGetProjects", region); op != nil {
					skipped = append(skipped, *op)
					continue
				}
				return fmt.Errorf("batch get projects in %s: %w", region, err)
			}
			for _, project := range detail.Projects {
				out.Send(buildCodeBuildProjectResource(project, accountID, region))
			}
		}
	}

	l.skipReport.RecordBatch(skipped)
	return nil
}

// chunkStrings splits s into consecutive slices of at most size elements. The final
// chunk may be shorter. A non-positive size returns a single chunk.
func chunkStrings(s []string, size int) [][]string {
	if size <= 0 {
		return [][]string{s}
	}
	var chunks [][]string
	for size < len(s) {
		s, chunks = s[size:], append(chunks, s[:size:size])
	}
	if len(s) > 0 {
		chunks = append(chunks, s)
	}
	return chunks
}

func buildCodeBuildProjectResource(project codebuildtypes.Project, accountID, region string) output.AWSResource {
	name := aws.ToString(project.Name)

	// Arn is the full project ARN; fall back to a synthesized ARN if absent so the node
	// still keys cleanly (BatchGetProjects always returns the ARN).
	arn := aws.ToString(project.Arn)
	if arn == "" {
		arn = fmt.Sprintf("arn:aws:codebuild:%s:%s:project/%s", region, accountID, name)
	}

	return output.AWSResource{
		ResourceType: "AWS::CodeBuild::Project",
		ResourceID:   name,
		ARN:          arn,
		AccountRef:   accountID,
		Region:       region,
		DisplayName:  name,
		Properties: map[string]any{
			"Name": name,
			// ServiceRole is the role the project's builds assume; resource_service_role.yaml
			// substring-matches this quoted ARN value inside the flattened `properties` JSON
			// string to create the (Project)-[:HAS_ROLE]->(Role) edge.
			"ServiceRole": aws.ToString(project.ServiceRole),
		},
	}
}
