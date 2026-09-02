package enumeration

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

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

	// Without RegistryId, DescribeRepositories defaults to the caller's own
	// registry, so a cross-account ARN would either fail or silently resolve a
	// same-named repository in the caller's account and then attribute it to the
	// ARN's account.
	input := &ecr.DescribeRepositoriesInput{RepositoryNames: []string{name}}
	if parsed.AccountID != "" {
		input.RegistryId = aws.String(parsed.AccountID)
	}

	result, err := client.DescribeRepositories(context.Background(), input)
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
	details, skipped, err := ECRImages(context.Background(), client, aws.ToString(repo.RepositoryName), region)
	if err != nil {
		return output.AWSResource{}, nil, err
	}
	if skipped != nil {
		return buildECRRepositoryResource(repo, nil, nil, accountID, region), []SkippedOp{*skipped}, nil
	}

	var newest *ecrtypes.ImageDetail
	if len(details) > 0 {
		// ECRImages sorts most recently pushed first.
		newest = &details[0]
	}
	return buildECRRepositoryResource(repo, newest, imageWithTag(details, dockerDefaultTag), accountID, region), nil, nil
}

// imageWithTag returns the first image carrying tag, or nil if none does.
func imageWithTag(details []ecrtypes.ImageDetail, tag string) *ecrtypes.ImageDetail {
	for i := range details {
		if slices.Contains(details[i].ImageTags, tag) {
			return &details[i]
		}
	}
	return nil
}

// ECRImages returns every image in a repository, most recently pushed first.
// Images with no push timestamp sort last, since they cannot be ordered.
//
// It is exported because image SELECTION is a consumer's policy while talking to
// ECR is this package's job: ecr-dump uses it to scan every image, or one tag,
// rather than only the newest that the enumerated resource advertises.
//
// A skippable failure — a denial or a throttle — is returned as a non-nil
// SkippedOp with a nil error, so the caller records it and continues rather than
// treating an ECR permission boundary as a fatal error. Only unexpected failures
// come back as an error.
func ECRImages(ctx context.Context, client *ecr.Client, repoName, region string) ([]ecrtypes.ImageDetail, *SkippedOp, error) {
	var details []ecrtypes.ImageDetail
	paginator := ecr.NewDescribeImagesPaginator(client, &ecr.DescribeImagesInput{
		RepositoryName: aws.String(repoName),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if op := ClassifySkippable(err, "ecr", "DescribeImages", region); op != nil {
				return nil, op, nil
			}
			return nil, nil, fmt.Errorf("describe images in %s (%s): %w", repoName, region, err)
		}
		details = append(details, page.ImageDetails...)
	}

	sort.SliceStable(details, func(i, j int) bool {
		ti, tj := details[i].ImagePushedAt, details[j].ImagePushedAt
		if ti == nil || tj == nil {
			return ti != nil
		}
		return ti.After(*tj)
	})
	return details, nil, nil
}

// Properties keys published for consumers that pull an image. All are absent
// when the repository holds no images, or when DescribeImages was denied.
//
// Both references are published because "the newest image" and "the image a
// Docker client resolves" are different things: the former is whatever was
// pushed last, the latter is the "latest" tag. DescribeImages has already been
// called for LastModified, so publishing both costs nothing and spares the
// consumer a second call.
const (
	// ECRPropImageURI is the pull reference of the most recently pushed image,
	// e.g. 123456789012.dkr.ecr.us-east-2.amazonaws.com/app:v3.
	ECRPropImageURI = "NewestImageURI"
	// ECRPropImageTag is the tag component of ECRPropImageURI.
	ECRPropImageTag = "NewestImageTag"
	// ECRPropLatestTagURI is the pull reference of the image tagged "latest",
	// the tag a Docker client resolves when none is given. Absent when the
	// repository has no such tag, which is normal for version-tagged registries.
	ECRPropLatestTagURI = "LatestTagImageURI"
	// ECRPropLatestTagPushedAt is the RFC3339Nano push time of the image tagged
	// "latest". LastModified tracks the NEWEST push, which is often a different
	// image, so an incremental consumer needs this to tell whether the image it
	// resolves has itself changed.
	ECRPropLatestTagPushedAt = "LatestTagPushedAt"

	// ECRPropImageDigest and ECRPropLatestTagDigest are the content digests of
	// the images the two references above point at.
	//
	// A digest is the image's content hash, so it is IMMUTABLE: the bytes behind
	// sha256:abc… can never change. That makes it a stronger scan key than any
	// timestamp — a consumer that has scanned a digest never needs to scan it
	// again, whereas a push time only says the repository changed, not that the
	// image a tag resolves to did. Publishing both digests lets a consumer skip
	// exactly, instead of re-pulling because some sibling tag moved.
	ECRPropImageDigest     = "NewestImageDigest"
	ECRPropLatestTagDigest = "LatestTagImageDigest"
)

// dockerDefaultTag is the tag a container client resolves when a reference
// carries none.
const dockerDefaultTag = "latest"

func buildECRRepositoryResource(repo ecrtypes.Repository, newest, latestTagged *ecrtypes.ImageDetail, accountID, region string) output.AWSResource {
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

	// RepositoryUri is the authoritative registry host and path; building
	// references from it avoids reconstructing the ECR endpoint by hand.
	repoURI := aws.ToString(repo.RepositoryUri)

	if newest != nil {
		// An image pushed by digest carries no tag, and ECR does NOT resolve it
		// under "latest". Defaulting the tag would publish a reference that
		// either fails to pull or, worse, silently resolves to a different and
		// older image. Reference it by digest instead.
		if repoURI != "" {
			if len(newest.ImageTags) > 0 {
				properties[ECRPropImageURI] = fmt.Sprintf("%s:%s", repoURI, newest.ImageTags[0])
			} else if digest := aws.ToString(newest.ImageDigest); digest != "" {
				properties[ECRPropImageURI] = fmt.Sprintf("%s@%s", repoURI, digest)
			}
		}
		if len(newest.ImageTags) > 0 {
			properties[ECRPropImageTag] = newest.ImageTags[0]
		} else if digest := aws.ToString(newest.ImageDigest); digest != "" {
			properties[ECRPropImageTag] = digest
		}
		if digest := aws.ToString(newest.ImageDigest); digest != "" {
			properties[ECRPropImageDigest] = digest
		}
		resource.LastModified = newest.ImagePushedAt
	}

	if latestTagged != nil && repoURI != "" {
		properties[ECRPropLatestTagURI] = fmt.Sprintf("%s:%s", repoURI, dockerDefaultTag)
		// The "latest" tag and the newest push are frequently different images,
		// so an incremental consumer needs this image's own push time to decide
		// whether the image it is about to pull actually changed.
		if latestTagged.ImagePushedAt != nil {
			properties[ECRPropLatestTagPushedAt] = latestTagged.ImagePushedAt.UTC().Format(time.RFC3339Nano)
		}
		if digest := aws.ToString(latestTagged.ImageDigest); digest != "" {
			properties[ECRPropLatestTagDigest] = digest
		}
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
