package recon

import (
	"archive/tar"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/ecrpublic"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/secrets"
	"github.com/praetorian-inc/titus/pkg/types"
)

func init() {
	plugin.Register(&AWSECRDumpModule{})
}

type ECRDumpConfig struct {
	plugin.AWSCommonRecon
	secrets.ScannerConfig
	Extract bool `param:"extract" desc:"Extract image layers to filesystem" default:"true"`
}

type AWSECRDumpModule struct {
	ECRDumpConfig
}

func (m *AWSECRDumpModule) ID() string                { return "ecr-dump" }
func (m *AWSECRDumpModule) Name() string              { return "AWS ECR Dump" }
func (m *AWSECRDumpModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AWSECRDumpModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *AWSECRDumpModule) OpsecLevel() string        { return "moderate" }
func (m *AWSECRDumpModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AWSECRDumpModule) Description() string {
	return "Dump ECR container filesystems to disk and scan for secrets using Titus. " +
		"Supports both private and public ECR repositories. " +
		"Uses go-containerregistry (no Docker daemon required)."
}

func (m *AWSECRDumpModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/AmazonECR/latest/userguide/docker-pull-ecr-image.html",
		"https://github.com/google/go-containerregistry",
	}
}

func (m *AWSECRDumpModule) SupportedResourceTypes() []string {
	return []string{
		"AWS::ECR::Repository",
		"AWS::ECR::PublicRepository",
	}
}

func (m *AWSECRDumpModule) Parameters() any {
	return &m.ECRDumpConfig
}

// ecrImage holds a resolved image reference with its auth and metadata.
type ecrImage struct {
	RepoName  string
	Region    string
	AccountID string
	ImageURI  string
	Tag       string
	Auth      authn.Authenticator
	IsPublic  bool
}

// scanFinding tracks a finding for console summary output.
type scanFinding struct {
	RuleName string
	FindingID string
	Label    string
	Resource string
	Region   string
	Before   string
	Matching string
	After    string
}

func (m *AWSECRDumpModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.ECRDumpConfig
	if c.DBPath == "" {
		c.DBPath = secrets.DefaultDBPath(c.OutputDir)
	}

	var scanner secrets.SecretScanner
	if err := scanner.Start(c.ScannerConfig); err != nil {
		return fmt.Errorf("failed to create Titus scanner: %w", err)
	}
	defer func() {
		if closeErr := scanner.Close(); closeErr != nil {
			slog.Warn("failed to close Titus scanner", "error", closeErr)
		}
	}()

	outputDir := filepath.Join(c.OutputDir, "ecr-images")
	var allFindings []scanFinding

	for _, region := range m.Regions {
		awsCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
			Region:     region,
			Profile:    m.Profile,
			ProfileDir: m.ProfileDir,
		})
		if err != nil {
			cfg.Warn("failed to load AWS config for %s: %v", region, err)
			continue
		}

		ctx := context.TODO()

		// --- Private ECR repositories ---
		privateClient := ecr.NewFromConfig(awsCfg)
		repos, err := listECRRepos(ctx, privateClient)
		if err != nil {
			cfg.Warn("failed to list private ECR repos in %s: %v", region, err)
		}

		if len(repos) > 0 {
			cfg.Info("found %d private ECR repos in %s", len(repos), region)

			auth, accountID, err := getECRAuth(ctx, privateClient)
			if err != nil {
				cfg.Warn("failed to get private ECR auth in %s: %v", region, err)
			} else {
				for _, repo := range repos {
					findings := m.processPrivateRepo(cfg, ctx, privateClient, repo, region, accountID, auth, outputDir, &scanner, out)
					allFindings = append(allFindings, findings...)
				}
			}
		}

		// --- Public ECR repositories (only from us-east-1) ---
		if region == "us-east-1" {
			publicCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
				Region:     "us-east-1",
				Profile:    m.Profile,
				ProfileDir: m.ProfileDir,
			})
			if err == nil {
				publicClient := ecrpublic.NewFromConfig(publicCfg)
				publicFindings := m.processPublicRepos(cfg, ctx, publicClient, outputDir, &scanner, out)
				allFindings = append(allFindings, publicFindings...)
			}
		}
	}

	// Print console summary grouped by rule (matches Nebula's NPFindingsConsoleOutputter).
	printFindingsSummary(cfg, allFindings)

	return nil
}

func (m *AWSECRDumpModule) processPrivateRepo(
	cfg plugin.Config, ctx context.Context, client *ecr.Client,
	repo ecrtypes.Repository, region, accountID string,
	auth authn.Authenticator, outputDir string,
	scanner *secrets.SecretScanner, out *pipeline.P[model.AurelianModel],
) []scanFinding {
	repoName := valStr(repo.RepositoryName)
	if repoName == "" {
		return nil
	}

	imageURI, tag, err := getLatestImage(ctx, client, repoName, region, accountID)
	if err != nil {
		cfg.Warn("no images in %s: %v", repoName, err)
		return nil
	}

	cfg.Info("pulling %s:%s", repoName, tag)

	img := ecrImage{
		RepoName:  repoName,
		Region:    region,
		AccountID: accountID,
		ImageURI:  imageURI,
		Tag:       tag,
		Auth:      auth,
	}

	return m.pullExtractScan(cfg, img, outputDir, scanner, out)
}

func (m *AWSECRDumpModule) processPublicRepos(
	cfg plugin.Config, ctx context.Context, client *ecrpublic.Client,
	outputDir string, scanner *secrets.SecretScanner, out *pipeline.P[model.AurelianModel],
) []scanFinding {
	repos, err := listPublicECRRepos(ctx, client)
	if err != nil {
		cfg.Warn("failed to list public ECR repos: %v", err)
		return nil
	}
	if len(repos) == 0 {
		return nil
	}

	cfg.Info("found %d public ECR repos", len(repos))

	auth, err := getPublicECRAuth(ctx, client)
	if err != nil {
		cfg.Warn("failed to get public ECR auth: %v", err)
		return nil
	}

	var allFindings []scanFinding
	for _, repo := range repos {
		repoName := valStr(repo.RepositoryName)
		repoURI := valStr(repo.RepositoryUri)
		if repoName == "" || repoURI == "" {
			continue
		}

		// Extract registryAlias from URI: public.ecr.aws/{alias}/{repo}
		registryAlias := ""
		if parts := strings.Split(strings.TrimPrefix(repoURI, "public.ecr.aws/"), "/"); len(parts) > 0 {
			registryAlias = parts[0]
		}

		imageURI, tag, err := getLatestPublicImage(ctx, client, repoName, registryAlias)
		if err != nil {
			cfg.Warn("no images in public repo %s: %v", repoName, err)
			continue
		}

		cfg.Info("pulling public %s:%s", repoName, tag)

		// Get registryId as accountID for public repos.
		accountID := valStr(repo.RegistryId)

		img := ecrImage{
			RepoName:  repoName,
			Region:    "us-east-1",
			AccountID: accountID,
			ImageURI:  imageURI,
			Tag:       tag,
			Auth:      auth,
			IsPublic:  true,
		}

		findings := m.pullExtractScan(cfg, img, outputDir, scanner, out)
		allFindings = append(allFindings, findings...)
	}
	return allFindings
}

func (m *AWSECRDumpModule) pullExtractScan(
	cfg plugin.Config, img ecrImage, outputDir string,
	scanner *secrets.SecretScanner, out *pipeline.P[model.AurelianModel],
) []scanFinding {
	extractDir := filepath.Join(outputDir, sanitizeName(img.RepoName))
	scanInputs, err := pullAndExtract(img, extractDir, m.Extract)
	if err != nil {
		cfg.Warn("failed to pull/extract %s: %v", img.RepoName, err)
		return nil
	}

	cfg.Success("extracted %d files from %s", len(scanInputs), img.RepoName)

	var findings []scanFinding
	for _, si := range scanInputs {
		scanPipeline := pipeline.From(si)
		scanned := pipeline.New[secrets.SecretScanResult]()
		pipeline.Pipe(scanPipeline, scanner.Scan, scanned)

		results, err := scanned.Collect()
		if err != nil {
			slog.Warn("scan error", "repo", img.RepoName, "error", err)
			continue
		}

		for _, result := range results {
			proof := buildECRProofData(result, result.Match)
			proofBytes, err := json.MarshalIndent(proof, "", "  ")
			if err != nil {
				continue
			}
			out.Send(secrets.NewSecretRisk(result, "aws", proofBytes))

			ruleName := result.Match.RuleName
			if ruleName == "" {
				ruleName = result.Match.RuleID
			}
			findings = append(findings, scanFinding{
				RuleName:  ruleName,
				FindingID: result.Match.FindingID,
				Label:     result.Label,
				Resource:  result.ResourceRef,
				Region:    result.Region,
				Before:    truncate(string(result.Match.Snippet.Before), 50),
				Matching:  truncate(string(result.Match.Snippet.Matching), 60),
				After:     truncate(string(result.Match.Snippet.After), 50),
			})
		}
	}
	return findings
}

// printFindingsSummary outputs findings grouped by rule name, matching Nebula's NPFindingsConsoleOutputter.
func printFindingsSummary(cfg plugin.Config, findings []scanFinding) {
	if len(findings) == 0 {
		cfg.Success("ECR dump complete — no secrets found")
		return
	}

	// Group by rule name.
	grouped := make(map[string][]scanFinding)
	var ruleOrder []string
	for _, f := range findings {
		if _, exists := grouped[f.RuleName]; !exists {
			ruleOrder = append(ruleOrder, f.RuleName)
		}
		grouped[f.RuleName] = append(grouped[f.RuleName], f)
	}
	sort.Strings(ruleOrder)

	cfg.Info("--- Secret Scan Findings ---")
	for _, ruleName := range ruleOrder {
		ruleFindings := grouped[ruleName]
		cfg.Info("")
		cfg.Info("Rule: %s (%d findings)", ruleName, len(ruleFindings))
		for i, f := range ruleFindings {
			cfg.Info("  [%d/%d] %s", i+1, len(ruleFindings), f.FindingID[:min(8, len(f.FindingID))])
			cfg.Info("    Location: %s | %s | %s", f.Region, f.Resource, f.Label)
			cfg.Info("    Context: ...%s[%s]%s...", f.Before, f.Matching, f.After)
		}
	}

	cfg.Success("ECR dump complete — %d findings across %d rules", len(findings), len(ruleOrder))
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// --- Private ECR functions ---

func listECRRepos(ctx context.Context, client *ecr.Client) ([]ecrtypes.Repository, error) {
	var repos []ecrtypes.Repository
	paginator := ecr.NewDescribeRepositoriesPaginator(client, &ecr.DescribeRepositoriesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return repos, err
		}
		repos = append(repos, page.Repositories...)
	}
	return repos, nil
}

func getECRAuth(ctx context.Context, client *ecr.Client) (authn.Authenticator, string, error) {
	resp, err := client.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return nil, "", fmt.Errorf("GetAuthorizationToken: %w", err)
	}
	if len(resp.AuthorizationData) == 0 {
		return nil, "", fmt.Errorf("no authorization data returned")
	}

	authData := resp.AuthorizationData[0]
	decoded, err := base64.StdEncoding.DecodeString(valStr(authData.AuthorizationToken))
	if err != nil {
		return nil, "", fmt.Errorf("decoding auth token: %w", err)
	}

	// Token format: "AWS:<password>"
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return nil, "", fmt.Errorf("unexpected auth token format")
	}

	// Extract account ID from proxy endpoint.
	endpoint := valStr(authData.ProxyEndpoint)
	accountID := ""
	if strings.Contains(endpoint, ".dkr.ecr.") {
		endpoint = strings.TrimPrefix(endpoint, "https://")
		accountID, _, _ = strings.Cut(endpoint, ".")
	}

	auth := authn.FromConfig(authn.AuthConfig{
		Username: parts[0],
		Password: parts[1],
	})

	return auth, accountID, nil
}

func getLatestImage(ctx context.Context, client *ecr.Client, repoName, region, accountID string) (string, string, error) {
	resp, err := client.DescribeImages(ctx, &ecr.DescribeImagesInput{
		RepositoryName: &repoName,
		MaxResults:     intPtr(1000),
	})
	if err != nil {
		return "", "", err
	}
	if len(resp.ImageDetails) == 0 {
		return "", "", fmt.Errorf("no images found")
	}

	// Sort by push time, newest first.
	sort.Slice(resp.ImageDetails, func(i, j int) bool {
		ti := resp.ImageDetails[i].ImagePushedAt
		tj := resp.ImageDetails[j].ImagePushedAt
		if ti == nil || tj == nil {
			return ti != nil
		}
		return ti.After(*tj)
	})

	latest := resp.ImageDetails[0]
	tag := "latest"
	if len(latest.ImageTags) > 0 {
		tag = latest.ImageTags[0]
	}

	imageURI := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/%s:%s", accountID, region, repoName, tag)
	return imageURI, tag, nil
}

// --- Public ECR functions ---

func listPublicECRRepos(ctx context.Context, client *ecrpublic.Client) ([]ecrpublicRepo, error) {
	var repos []ecrpublicRepo
	resp, err := client.DescribeRepositories(ctx, &ecrpublic.DescribeRepositoriesInput{})
	if err != nil {
		return nil, err
	}
	for _, r := range resp.Repositories {
		repos = append(repos, ecrpublicRepo{
			RepositoryName: r.RepositoryName,
			RepositoryUri:  r.RepositoryUri,
			RegistryId:     r.RegistryId,
		})
	}
	return repos, nil
}

type ecrpublicRepo struct {
	RepositoryName *string
	RepositoryUri  *string
	RegistryId     *string
}

func getPublicECRAuth(ctx context.Context, client *ecrpublic.Client) (authn.Authenticator, error) {
	resp, err := client.GetAuthorizationToken(ctx, &ecrpublic.GetAuthorizationTokenInput{})
	if err != nil {
		return nil, fmt.Errorf("public GetAuthorizationToken: %w", err)
	}
	if resp.AuthorizationData == nil || resp.AuthorizationData.AuthorizationToken == nil {
		return nil, fmt.Errorf("no public authorization data returned")
	}

	decoded, err := base64.StdEncoding.DecodeString(*resp.AuthorizationData.AuthorizationToken)
	if err != nil {
		return nil, fmt.Errorf("decoding public auth token: %w", err)
	}

	auth := authn.FromConfig(authn.AuthConfig{
		Username: "AWS",
		Password: string(decoded),
	})

	return auth, nil
}

func getLatestPublicImage(ctx context.Context, client *ecrpublic.Client, repoName, registryAlias string) (string, string, error) {
	resp, err := client.DescribeImages(ctx, &ecrpublic.DescribeImagesInput{
		RepositoryName: &repoName,
	})
	if err != nil {
		return "", "", err
	}
	if len(resp.ImageDetails) == 0 {
		return "", "", fmt.Errorf("no images found")
	}

	// Sort by push time, newest first.
	sort.Slice(resp.ImageDetails, func(i, j int) bool {
		ti := resp.ImageDetails[i].ImagePushedAt
		tj := resp.ImageDetails[j].ImagePushedAt
		if ti == nil || tj == nil {
			return ti != nil
		}
		return ti.After(*tj)
	})

	latest := resp.ImageDetails[0]
	tag := "latest"
	if len(latest.ImageTags) > 0 {
		tag = latest.ImageTags[0]
	}

	imageURI := fmt.Sprintf("public.ecr.aws/%s/%s:%s", registryAlias, repoName, tag)
	return imageURI, tag, nil
}

// --- Shared functions ---

func pullAndExtract(img ecrImage, extractDir string, extractToFS bool) ([]output.ScanInput, error) {
	ref, err := name.ParseReference(img.ImageURI)
	if err != nil {
		return nil, fmt.Errorf("parsing image ref: %w", err)
	}

	remoteImg, err := remote.Image(ref, remote.WithAuth(img.Auth))
	if err != nil {
		return nil, fmt.Errorf("pulling image: %w", err)
	}

	layers, err := remoteImg.Layers()
	if err != nil {
		return nil, fmt.Errorf("getting layers: %w", err)
	}

	if extractToFS {
		if err := os.MkdirAll(extractDir, 0o750); err != nil {
			return nil, fmt.Errorf("creating extract dir: %w", err)
		}
	}

	var scanInputs []output.ScanInput
	resourceType := "AWS::ECR::Repository"
	if img.IsPublic {
		resourceType = "AWS::ECR::PublicRepository"
	}
	arn := fmt.Sprintf("arn:aws:ecr:%s:%s:repository/%s", img.Region, img.AccountID, img.RepoName)

	for i, layer := range layers {
		rc, err := layer.Uncompressed()
		if err != nil {
			slog.Warn("failed to read layer", "layer", i, "error", err)
			continue
		}

		inputs, err := extractLayer(rc, extractDir, extractToFS, arn, img.Region, img.AccountID, img.RepoName, resourceType, i)
		rc.Close()
		if err != nil {
			slog.Warn("failed to extract layer", "layer", i, "error", err)
			continue
		}
		scanInputs = append(scanInputs, inputs...)
	}

	return scanInputs, nil
}

func extractLayer(r io.Reader, extractDir string, extractToFS bool, arn, region, accountID, repoName, resourceType string, layerIdx int) ([]output.ScanInput, error) {
	tr := tar.NewReader(r)
	var scanInputs []output.ScanInput

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return scanInputs, err
		}

		if hdr.Typeflag != tar.TypeReg || hdr.Size == 0 {
			continue
		}

		// Skip large files (>10MB).
		if hdr.Size > 10*1024*1024 {
			continue
		}

		content, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
		if err != nil {
			continue
		}

		if isBinary(content) {
			continue
		}

		if extractToFS {
			outPath := filepath.Join(extractDir, fmt.Sprintf("layer%d", layerIdx), filepath.Clean(hdr.Name))
			if err := writeExtractedFile(outPath, content); err != nil {
				slog.Debug("failed to write extracted file", "path", outPath, "error", err)
			}
		}

		label := fmt.Sprintf("%s:layer%d/%s", repoName, layerIdx, hdr.Name)
		scanInputs = append(scanInputs, output.ScanInput{
			Content:      content,
			ResourceID:   arn,
			ResourceType: resourceType,
			Region:       region,
			AccountID:    accountID,
			Label:        label,
		})
	}

	return scanInputs, nil
}

func writeExtractedFile(path string, content []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, content, 0o600)
}

// isBinary checks if content appears to be binary (contains null bytes in first 512 bytes).
func isBinary(content []byte) bool {
	check := content
	if len(check) > 512 {
		check = check[:512]
	}
	for _, b := range check {
		if b == 0 {
			return true
		}
	}
	return false
}

func sanitizeName(s string) string {
	r := strings.NewReplacer("/", "_", ":", "_", ".", "_")
	return r.Replace(s)
}

func valStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func intPtr(i int32) *int32 { return &i }

func buildECRProofData(result secrets.SecretScanResult, match *types.Match) map[string]interface{} {
	return map[string]interface{}{
		"finding_id":   match.FindingID,
		"rule_name":    match.RuleName,
		"rule_text_id": match.RuleID,
		"resource_ref": result.ResourceRef,
		"num_matches":  1,
		"matches": []map[string]interface{}{
			{
				"provenance": []map[string]interface{}{
					{
						"kind":          "container_image",
						"platform":      "aws",
						"resource_id":   result.ResourceRef,
						"resource_type": result.ResourceType,
						"region":        result.Region,
						"account_id":    result.AccountID,
						"first_commit": map[string]interface{}{
							"blob_path": result.Label,
						},
					},
				},
				"snippet": map[string]string{
					"before":   string(match.Snippet.Before),
					"matching": string(match.Snippet.Matching),
					"after":    string(match.Snippet.After),
				},
			},
		},
	}
}
