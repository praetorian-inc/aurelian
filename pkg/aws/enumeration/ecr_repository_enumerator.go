package enumeration

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/ratelimit"
)

// ECRRepositoryEnumerator enumerates private ECR repositories using the native
// ECR SDK. CloudControl's AWS::ECR::Repository description carries neither the
// repository's images nor a modification time, so a consumer behind the
// fallback has nothing to compare against a modified-since checkpoint and would
// re-pull every image on every run.
//
// DescribeImages is called once per repository to resolve the most recently
// pushed image. Its ImagePushedAt becomes LastModified, and its pull URI and tag
// are published in Properties so a consumer can pull the image without
// repeating the call.
//
// Public repositories are deliberately out of scope: ECR Public has a single
// us-east-1 control plane (ecr-public.amazonaws.com), so it does not fit this
// enumerator's per-region fan-out. The ecr-dump module enumerates them itself.
type ECRRepositoryEnumerator struct {
	plugin.AWSCommonRecon
	provider   *AWSConfigProvider
	skipReport *SkipReport
}

// NewECRRepositoryEnumerator creates an ECRRepositoryEnumerator that uses the native ECR SDK.
func NewECRRepositoryEnumerator(opts plugin.AWSCommonRecon, provider *AWSConfigProvider, skipReport *SkipReport) *ECRRepositoryEnumerator {
	return &ECRRepositoryEnumerator{
		AWSCommonRecon: opts,
		provider:       provider,
		skipReport:     skipReport,
	}
}

// ResourceType returns the CloudControl type string for private ECR repositories.
func (l *ECRRepositoryEnumerator) ResourceType() string {
	return "AWS::ECR::Repository"
}

// EnumerateAll enumerates every private ECR repository in the account across configured regions.
func (l *ECRRepositoryEnumerator) EnumerateAll(out *pipeline.P[output.AWSResource]) error {
	if len(l.Regions) == 0 {
		return fmt.Errorf("no regions configured")
	}

	accountID, err := l.provider.GetAccountID(l.Regions[0])
	if err != nil {
		return fmt.Errorf("get account ID: %w", err)
	}

	actor := ratelimit.NewCrossRegionActor(l.Concurrency)
	return actor.ActInRegions(l.Regions, func(region string) error {
		return l.listRepositoriesInRegion(region, accountID, out)
	})
}

// EnumerateByARN fetches a single repository by ARN.
func (l *ECRRepositoryEnumerator) EnumerateByARN(arn string, out *pipeline.P[output.AWSResource]) error {
	parsed, err := awsarn.Parse(arn)
	if err != nil {
		return fmt.Errorf("parse ARN %q: %w", arn, err)
	}
	name, ok := strings.CutPrefix(parsed.Resource, "repository/")
	if !ok || name == "" {
		return fmt.Errorf("invalid ECR repository ARN resource: %q", parsed.Resource)
	}
	if parsed.Region == "" {
		return fmt.Errorf("ECR repository ARN missing region: %q", arn)
	}

	cfg, err := l.provider.GetAWSConfig(parsed.Region)
	if err != nil {
		return fmt.Errorf("create ECR client for %s: %w", parsed.Region, err)
	}
	client := ecr.NewFromConfig(*cfg)

	result, err := client.DescribeRepositories(context.Background(), &ecr.DescribeRepositoriesInput{
		RepositoryNames: []string{name},
	})
	if err != nil {
		if op := ClassifySkippable(err, "ecr", "DescribeRepositories", parsed.Region); op != nil {
			l.skipReport.Record(*op)
			return nil
		}
		return fmt.Errorf("describe repository %s: %w", arn, err)
	}
	if len(result.Repositories) == 0 {
		return fmt.Errorf("describe repository %s returned no repositories", arn)
	}

	resource, skipped, err := l.describeRepository(client, result.Repositories[0], parsed.AccountID, parsed.Region)
	if err != nil {
		return err
	}
	l.skipReport.RecordBatch(skipped)
	out.Send(resource)
	return nil
}

func (l *ECRRepositoryEnumerator) listRepositoriesInRegion(region, accountID string, out *pipeline.P[output.AWSResource]) error {
	cfg, err := l.provider.GetAWSConfig(region)
	if err != nil {
		return fmt.Errorf("create ECR client for %s: %w", region, err)
	}
	client := ecr.NewFromConfig(*cfg)

	paginator := ecr.NewDescribeRepositoriesPaginator(client, &ecr.DescribeRepositoriesInput{})
	var skipped []SkippedOp
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			if op := ClassifySkippable(err, "ecr", "DescribeRepositories", region); op != nil {
				skipped = append(skipped, *op)
				break
			}
			return fmt.Errorf("describe repositories in %s: %w", region, err)
		}
		for _, repo := range page.Repositories {
			resource, repoSkipped, err := l.describeRepository(client, repo, accountID, region)
			if err != nil {
				return err
			}
			skipped = append(skipped, repoSkipped...)
			out.Send(resource)
		}
	}

	l.skipReport.RecordBatch(skipped)
	return nil
}

// describeRepository resolves a repository's newest image and builds its resource.
// A DescribeImages denial is returned as a skip rather than an error: the
// repository itself was enumerated successfully and belongs in the inventory,
// but its LastModified is left nil so a modified-since consumer fails open and
// scans it instead of silently treating it as unchanged.
func (l *ECRRepositoryEnumerator) describeRepository(client *ecr.Client, repo ecrtypes.Repository, accountID, region string) (output.AWSResource, []SkippedOp, error) {
	newest, err := newestImage(client, aws.ToString(repo.RepositoryName))
	if err != nil {
		if op := ClassifySkippable(err, "ecr", "DescribeImages", region); op != nil {
			return buildECRRepositoryResource(repo, nil, accountID, region), []SkippedOp{*op}, nil
		}
		return output.AWSResource{}, nil, fmt.Errorf("describe images in %s (%s): %w",
			aws.ToString(repo.RepositoryName), region, err)
	}
	return buildECRRepositoryResource(repo, newest, accountID, region), nil, nil
}

// newestImage returns the most recently pushed image in a repository, or nil
// when the repository holds none.
func newestImage(client *ecr.Client, repoName string) (*ecrtypes.ImageDetail, error) {
	var details []ecrtypes.ImageDetail
	paginator := ecr.NewDescribeImagesPaginator(client, &ecr.DescribeImagesInput{
		RepositoryName: aws.String(repoName),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.Background())
		if err != nil {
			return nil, err
		}
		details = append(details, page.ImageDetails...)
	}
	if len(details) == 0 {
		return nil, nil
	}

	sort.Slice(details, func(i, j int) bool {
		ti, tj := details[i].ImagePushedAt, details[j].ImagePushedAt
		if ti == nil || tj == nil {
			return ti != nil
		}
		return ti.After(*tj)
	})
	return &details[0], nil
}

// Properties keys published for consumers that pull the newest image. They are
// absent when the repository holds no images, or when DescribeImages was denied.
const (
	// ECRPropImageURI is the fully qualified pull reference, e.g.
	// 123456789012.dkr.ecr.us-east-2.amazonaws.com/app:v3.
	ECRPropImageURI = "NewestImageURI"
	// ECRPropImageTag is the tag component of ECRPropImageURI.
	ECRPropImageTag = "NewestImageTag"
)

func buildECRRepositoryResource(repo ecrtypes.Repository, newest *ecrtypes.ImageDetail, accountID, region string) output.AWSResource {
	name := aws.ToString(repo.RepositoryName)

	properties := map[string]any{
		"RepositoryName": name,
		"RepositoryUri":  aws.ToString(repo.RepositoryUri),
	}
	if repo.ImageTagMutability != "" {
		properties["ImageTagMutability"] = string(repo.ImageTagMutability)
	}

	resource := output.AWSResource{
		ResourceType: "AWS::ECR::Repository",
		ResourceID:   name,
		ARN:          repositoryARN(repo, accountID, region, name),
		AccountRef:   accountID,
		Region:       region,
		DisplayName:  name,
		Properties:   properties,
	}

	if newest != nil {
		tag := "latest"
		if len(newest.ImageTags) > 0 {
			tag = newest.ImageTags[0]
		}
		// RepositoryUri is the authoritative registry host and path; building the
		// reference from it avoids reconstructing the ECR endpoint by hand.
		if uri := aws.ToString(repo.RepositoryUri); uri != "" {
			properties[ECRPropImageURI] = fmt.Sprintf("%s:%s", uri, tag)
		}
		properties[ECRPropImageTag] = tag
		resource.LastModified = newest.ImagePushedAt
	}

	return resource
}

// repositoryARN prefers the ARN reported by AWS and synthesizes one only if it
// is absent, so the node still keys cleanly.
func repositoryARN(repo ecrtypes.Repository, accountID, region, name string) string {
	if arn := aws.ToString(repo.RepositoryArn); arn != "" {
		return arn
	}
	return fmt.Sprintf("arn:aws:ecr:%s:%s:repository/%s", region, accountID, name)
}
