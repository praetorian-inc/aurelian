package recon

import (
	"archive/tar"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecrpublic"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	cclist "github.com/praetorian-inc/aurelian/pkg/aws/enumeration"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/secrets"
)

func init() {
	plugin.Register(&AWSECRDumpModule{})
}

type ECRDumpConfig struct {
	plugin.AWSCommonRecon
	secrets.ScannerConfig
	Extract       bool   `param:"extract" desc:"Extract image layers to filesystem" default:"true"`
	Images        string `param:"images" desc:"Which images to scan per repository: \"newest\" (most recently pushed), \"all\", or a tag name such as \"latest\"" default:"newest"`
	ModifiedSince string `param:"modified-since" desc:"RFC3339 timestamp of the last successful scan; repositories whose newest image was pushed no later than this are skipped"`
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
	ARN       string
	ImageURI  string
	Tag       string
	Auth      authn.Authenticator
	IsPublic  bool
}

// Reserved values for --images. Anything else is taken as a tag name, so
// `--images latest` selects the image tagged "latest" rather than the most
// recently pushed one, which is frequently a different image.
const (
	imagesNewest = "newest"
	imagesAll    = "all"
)

// regionSession holds the per-region ECR client and registry authenticator.
// GetAuthorizationToken issues a 12-hour token, so one call per region covers an
// entire run no matter how many repositories or images it visits.
type regionSession struct {
	client *ecr.Client
	auth   authn.Authenticator
}

// ecrDumpRun carries the per-invocation state every enumeration helper needs.
type ecrDumpRun struct {
	cfg           plugin.Config
	out           *pipeline.P[model.AurelianModel]
	scanner       *secrets.SecretScanner
	outputDir     string
	extract       bool
	modifiedSince time.Time
	incremental   bool
	images        string
	profile       string
	profileDir    string
	sessions      map[string]*regionSession
}

// mode returns the effective --images selection. An unset value behaves as the
// documented default rather than as a tag selector matching nothing, so a run is
// safe however it was constructed.
func (r *ecrDumpRun) mode() string {
	if r.images == "" {
		return imagesNewest
	}
	return r.images
}

// session returns the ECR client and authenticator for a region, resolving them
// at most once per run.
func (r *ecrDumpRun) session(region string) (*regionSession, error) {
	if s, ok := r.sessions[region]; ok {
		return s, nil
	}
	if r.sessions == nil {
		r.sessions = make(map[string]*regionSession)
	}

	awsCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
		Region:     region,
		Profile:    r.profile,
		ProfileDir: r.profileDir,
	})
	if err != nil {
		return nil, fmt.Errorf("load AWS config for %s: %w", region, err)
	}

	client := ecr.NewFromConfig(awsCfg)
	auth, err := getECRAuth(context.TODO(), client)
	if err != nil {
		return nil, err
	}

	s := &regionSession{client: client, auth: auth}
	r.sessions[region] = s
	return s, nil
}

// imageCandidate is the selection-relevant subset of an ECR image. The private
// and public registries return different SDK types, so both are mapped onto this
// and share one selection policy.
type imageCandidate struct {
	Tags     []string
	Digest   string
	PushedAt *time.Time
}

// chooseImages applies the --images policy plus the modified-since filter to a
// repository's images, which must arrive most-recently-pushed first. base
// carries the repository identity every returned image inherits.
func (r *ecrDumpRun) chooseImages(base ecrImage, repoURI string, candidates []imageCandidate) []ecrImage {
	wantTag := ""
	switch r.mode() {
	case imagesNewest:
		if len(candidates) == 0 {
			return nil
		}
		candidates = candidates[:1]
	case imagesAll:
	default:
		wantTag = r.mode()
	}

	var selected []ecrImage
	for _, candidate := range candidates {
		if wantTag != "" && !slices.Contains(candidate.Tags, wantTag) {
			continue
		}
		// An image pushed no later than the checkpoint cannot have changed, so
		// filter per image rather than only per repository.
		if r.skipUnchanged(candidate.PushedAt) {
			continue
		}

		img := base
		img.Tag, img.ImageURI = imageReference(repoURI, candidate, wantTag)
		if img.ImageURI == "" {
			// Neither a tag nor a digest: nothing pullable to reference.
			continue
		}
		selected = append(selected, img)
	}
	return selected
}

// selectImages resolves which images of a repository to scan.
//
// The default "newest" mode is answered entirely from the enumerated resource,
// so it costs no extra API call. "all" and tag selection need the repository's
// image list, which is fetched once. In every mode an image pushed no later than
// the modified-since checkpoint is dropped, so an incremental "all" run
// re-scans only the images that actually changed.
func (r *ecrDumpRun) selectImages(repo output.AWSResource) ([]ecrImage, error) {
	base := ecrImage{
		RepoName:  repo.ResourceID,
		Region:    repo.Region,
		AccountID: repo.AccountRef,
		ARN:       repo.ARN,
	}

	if r.mode() == imagesNewest {
		uri, _ := repo.Properties[cclist.ECRPropImageURI].(string)
		if uri == "" {
			// No published reference: the repository holds no images, or
			// DescribeImages was denied and recorded as a skip by the enumerator.
			return nil, nil
		}
		base.Tag, _ = repo.Properties[cclist.ECRPropImageTag].(string)
		base.ImageURI = uri
		return []ecrImage{base}, nil
	}

	session, err := r.session(repo.Region)
	if err != nil {
		return nil, err
	}
	details, skipped, err := cclist.ECRImages(context.TODO(), session.client, repo.ResourceID, repo.Region)
	if err != nil {
		return nil, err
	}
	if skipped != nil {
		// A denial or throttle here hides images the scan should have seen, so it
		// is a partial failure rather than an empty repository.
		return nil, fmt.Errorf("listing images in %s was skipped: %s %s in %s (%s)",
			repo.ResourceID, skipped.Service, skipped.Operation, skipped.Region, skipped.ErrorCode)
	}

	repoURI, _ := repo.Properties["RepositoryUri"].(string)
	if repoURI == "" {
		repoURI = fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com/%s", repo.AccountRef, repo.Region, repo.ResourceID)
	}

	candidates := make([]imageCandidate, 0, len(details))
	for _, detail := range details {
		candidates = append(candidates, imageCandidate{
			Tags:     detail.ImageTags,
			Digest:   aws.ToString(detail.ImageDigest),
			PushedAt: detail.ImagePushedAt,
		})
	}

	return r.chooseImages(base, repoURI, candidates), nil
}

// imageReference builds the pull reference for one image. It prefers the
// requested tag, then the image's first tag, and falls back to the digest for an
// image pushed without any tag.
func imageReference(repoURI string, candidate imageCandidate, wantTag string) (tag, uri string) {
	if wantTag != "" && slices.Contains(candidate.Tags, wantTag) {
		return wantTag, fmt.Sprintf("%s:%s", repoURI, wantTag)
	}
	if len(candidate.Tags) > 0 {
		return candidate.Tags[0], fmt.Sprintf("%s:%s", repoURI, candidate.Tags[0])
	}
	if candidate.Digest != "" {
		return candidate.Digest, fmt.Sprintf("%s@%s", repoURI, candidate.Digest)
	}
	return "", ""
}

// skipUnchanged reports whether an image pushed at pushedAt predates the
// modified-since checkpoint. An image with no push timestamp is never skipped:
// missing modification metadata must fail open, the same way a nil
// AWSResource.LastModified does in the shared AWS extractor.
func (r *ecrDumpRun) skipUnchanged(pushedAt *time.Time) bool {
	return r.incremental && pushedAt != nil && !pushedAt.After(r.modifiedSince)
}

// problem reports a partial-failure condition. A best-effort run logs it and
// carries on; an incremental run turns it into an error, because a caller that
// advances its modified-since checkpoint must never be told that a scan which
// skipped content succeeded.
func (r *ecrDumpRun) problem(format string, args ...any) error {
	if r.incremental {
		return fmt.Errorf(format, args...)
	}
	r.cfg.Warn(format, args...)
	return nil
}

// ref identifies an image within its repository, for scan labels and extract
// paths. A digest already carries its algorithm prefix, so it is used as-is.
func (i ecrImage) ref() string {
	if i.Tag == "" {
		return i.RepoName
	}
	return fmt.Sprintf("%s:%s", i.RepoName, i.Tag)
}

// scanFinding tracks a finding for console summary output.
type scanFinding struct {
	RuleName  string
	FindingID string
	Label     string
	Resource  string
	Region    string
	Before    string
	Matching  string
	After     string
}

func (m *AWSECRDumpModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) (runErr error) {
	c := m.ECRDumpConfig
	if c.DBPath == "" {
		c.DBPath = secrets.DefaultDBPath(c.OutputDir)
	}

	var modifiedSince time.Time
	incremental := c.ModifiedSince != ""
	if incremental {
		var parseErr error
		modifiedSince, parseErr = time.Parse(time.RFC3339Nano, c.ModifiedSince)
		if parseErr != nil {
			return fmt.Errorf("invalid modified-since timestamp %q: %w", c.ModifiedSince, parseErr)
		}
	}

	var scanner secrets.SecretScanner
	if err := scanner.Start(c.ScannerConfig); err != nil {
		return fmt.Errorf("failed to create Titus scanner: %w", err)
	}
	scanner.SetFailOnError(incremental)
	defer func() {
		if closeErr := scanner.Close(); closeErr != nil {
			slog.Warn("failed to close Titus scanner", "error", closeErr)
			if incremental {
				runErr = errors.Join(runErr, fmt.Errorf("close Titus scanner: %w", closeErr))
			}
		}
	}()

	run := &ecrDumpRun{
		cfg:           cfg,
		out:           out,
		scanner:       &scanner,
		outputDir:     filepath.Join(c.OutputDir, "ecr-images"),
		extract:       m.Extract,
		modifiedSince: modifiedSince,
		incremental:   incremental,
		images:        c.Images,
		profile:       m.Profile,
		profileDir:    m.ProfileDir,
		sessions:      make(map[string]*regionSession),
	}

	inputs, err := collectInputs(m.AWSCommonRecon, m.SupportedResourceTypes())
	if err != nil {
		return fmt.Errorf("failed to collect inputs: %w", err)
	}

	// AWS::ECR::PublicRepository has a single us-east-1 control plane and so no
	// per-region enumerator; this module enumerates it directly. Everything else
	// goes to the shared dispatcher, which resolves repository ARNs as well as
	// type names, and which reaches ECRRepositoryEnumerator for the private type.
	var listInputs []string
	scanPublic := false
	for _, input := range inputs {
		if input == "AWS::ECR::PublicRepository" {
			scanPublic = true
			continue
		}
		listInputs = append(listInputs, input)
	}

	var allFindings []scanFinding

	lister := cclist.NewEnumerator(c.AWSCommonRecon)
	defer func() { _ = lister.Close() }()

	if len(listInputs) > 0 {
		listOpts := &pipeline.PipeOpts{}
		if cfg.Log != nil {
			listOpts.Progress = cfg.Log.ProgressFunc("listing ECR repositories")
		}

		listed := pipeline.New[output.AWSResource]()
		pipeline.Pipe(pipeline.From(listInputs...), lister.List, listed, listOpts)

		// Drain the listing before pulling anything. Ranging while pulling would
		// leave the producer blocked on an unread channel if a pull fails and this
		// returns early; repository metadata is small enough to hold.
		repos, listErr := listed.Collect()
		if listErr != nil {
			return fmt.Errorf("listing ECR repositories: %w", listErr)
		}

		for _, repo := range repos {
			findings, err := m.processRepository(run, repo)
			allFindings = append(allFindings, findings...)
			if err != nil {
				return err
			}
		}
	}

	if scanPublic {
		publicCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
			Region:     "us-east-1",
			Profile:    m.Profile,
			ProfileDir: m.ProfileDir,
		})
		if err != nil {
			if fatal := run.problem("failed to load AWS config for public ECR: %v", err); fatal != nil {
				return fatal
			}
		} else {
			publicFindings, err := m.processPublicRepos(context.TODO(), run, ecrpublic.NewFromConfig(publicCfg))
			allFindings = append(allFindings, publicFindings...)
			if err != nil {
				return err
			}
		}
	}

	deferred, flushErr := flushDeferredMatches(&scanner)
	if flushErr != nil {
		if fatal := run.problem("failed to drain deferred secret matches: %v", flushErr); fatal != nil {
			return fatal
		}
	}
	allFindings = append(allFindings, emitResults(deferred, out)...)

	// Print console summary grouped by rule (matches Nebula's NPFindingsConsoleOutputter).
	printFindingsSummary(cfg, allFindings)

	// An incremental caller must not advance its checkpoint past repositories
	// that enumeration never reached. Same gate find-secrets applies.
	if incremental && lister.Skipped.Len() > 0 {
		return fmt.Errorf("resource enumeration was incomplete: %s", lister.Skipped.Summary())
	}

	return nil
}

// processRepository pulls, extracts and scans the newest image of one listed
// repository. The image reference and its push time come from the enumerated
// resource, so no ECR call is repeated here.
func (m *AWSECRDumpModule) processRepository(run *ecrDumpRun, repo output.AWSResource) ([]scanFinding, error) {
	// The newest push time bounds every image in the repository, so a repository
	// unchanged since the checkpoint can be skipped without listing its images at
	// all — whichever selection mode is in force.
	if run.skipUnchanged(repo.LastModified) {
		run.cfg.Info("skipping unchanged repository %s (newest image pushed %s)",
			repo.ResourceID, repo.LastModified.Format(time.RFC3339))
		return nil, nil
	}

	images, err := run.selectImages(repo)
	if err != nil {
		return nil, run.problem("failed to list images in %s: %v", repo.ResourceID, err)
	}
	if len(images) == 0 {
		run.cfg.Info("skipping %s: no images matched %q", repo.ResourceID, run.mode())
		return nil, nil
	}

	session, err := run.session(repo.Region)
	if err != nil {
		return nil, run.problem("failed to get private ECR auth in %s: %v", repo.Region, err)
	}

	var findings []scanFinding
	for _, img := range images {
		img.Auth = session.auth
		run.cfg.Info("pulling %s", img.ImageURI)

		imageFindings, err := m.pullExtractScan(run, img)
		findings = append(findings, imageFindings...)
		if err != nil {
			return findings, err
		}
	}
	return findings, nil
}

func (m *AWSECRDumpModule) processPublicRepos(
	ctx context.Context, run *ecrDumpRun, client *ecrpublic.Client,
) ([]scanFinding, error) {
	repos, err := listPublicECRRepos(ctx, client)
	if err != nil {
		return nil, run.problem("failed to list public ECR repos: %v", err)
	}
	if len(repos) == 0 {
		return nil, nil
	}

	run.cfg.Info("found %d public ECR repos", len(repos))

	auth, err := getPublicECRAuth(ctx, client)
	if err != nil {
		return nil, run.problem("failed to get public ECR auth: %v", err)
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

		candidates, err := publicImageCandidates(ctx, client, repoName)
		if err != nil {
			if fatal := run.problem("failed to describe images in public repo %s: %v", repoName, err); fatal != nil {
				return allFindings, fatal
			}
			continue
		}

		// registryAlias is unused for pulling — RepositoryUri already carries
		// public.ecr.aws/{alias}/{repo} — but it is kept for the log line.
		base := ecrImage{
			RepoName: repoName,
			Region:   "us-east-1",
			// Public repositories report the owning registry as RegistryId.
			AccountID: valStr(repo.RegistryId),
			Auth:      auth,
			IsPublic:  true,
		}

		images := run.chooseImages(base, repoURI, candidates)
		if len(images) == 0 {
			run.cfg.Info("skipping public repo %s/%s: no images matched %q", registryAlias, repoName, run.mode())
			continue
		}

		for _, img := range images {
			run.cfg.Info("pulling public %s", img.ImageURI)

			findings, err := m.pullExtractScan(run, img)
			allFindings = append(allFindings, findings...)
			if err != nil {
				return allFindings, err
			}
		}
	}
	return allFindings, nil
}

// publicImageCandidates lists a public repository's images, most recently
// pushed first.
func publicImageCandidates(ctx context.Context, client *ecrpublic.Client, repoName string) ([]imageCandidate, error) {
	resp, err := client.DescribeImages(ctx, &ecrpublic.DescribeImagesInput{
		RepositoryName: &repoName,
	})
	if err != nil {
		return nil, err
	}

	candidates := make([]imageCandidate, 0, len(resp.ImageDetails))
	for _, detail := range resp.ImageDetails {
		candidates = append(candidates, imageCandidate{
			Tags:     detail.ImageTags,
			Digest:   valStr(detail.ImageDigest),
			PushedAt: detail.ImagePushedAt,
		})
	}

	sort.SliceStable(candidates, func(i, j int) bool {
		ti, tj := candidates[i].PushedAt, candidates[j].PushedAt
		if ti == nil || tj == nil {
			return ti != nil
		}
		return ti.After(*tj)
	})
	return candidates, nil
}

func (m *AWSECRDumpModule) pullExtractScan(run *ecrDumpRun, img ecrImage) ([]scanFinding, error) {
	// Layers are numbered per image, so two images of one repository would both
	// write layer0/ and clobber each other. Give every image its own directory.
	extractDir := filepath.Join(run.outputDir, sanitizeName(img.RepoName), sanitizeName(img.Tag))
	scanInputs, err := pullAndExtract(img, extractDir, run.extract, run.incremental)
	if err != nil {
		return nil, run.problem("failed to pull/extract %s: %v", img.RepoName, err)
	}

	run.cfg.Success("extracted %d files from %s", len(scanInputs), img.RepoName)

	var findings []scanFinding
	for _, si := range scanInputs {
		scanPipeline := pipeline.From(si)
		scanned := pipeline.New[secrets.SecretScanResult]()
		pipeline.Pipe(scanPipeline, run.scanner.Scan, scanned)

		results, err := scanned.Collect()
		findings = append(findings, emitResults(results, run.out)...)
		if err != nil {
			if fatal := run.problem("failed to scan %s (%s): %v", img.RepoName, si.Label, err); fatal != nil {
				return findings, fatal
			}
			continue
		}
	}
	return findings, nil
}

// emitResults sends an AurelianRisk for every scan result and returns the
// corresponding console summary rows.
func emitResults(results []secrets.SecretScanResult, out *pipeline.P[model.AurelianModel]) []scanFinding {
	var findings []scanFinding
	for _, result := range results {
		risk, err := result.ToRisk()
		if err != nil {
			slog.Warn("failed to build risk", "resource", result.ResourceRef, "error", err)
			continue
		}
		out.Send(risk)

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
	return findings
}

// flushDeferredMatches drains the matches Titus withholds behind its
// regexp-timeout retry queue. Call once after every Scan has completed and
// before the scanner is closed; without the drain those matches are dropped.
func flushDeferredMatches(scanner *secrets.SecretScanner) ([]secrets.SecretScanResult, error) {
	flushed := pipeline.New[secrets.SecretScanResult]()
	var flushErr error
	go func() {
		flushErr = scanner.Flush(flushed)
		flushed.Close()
	}()

	results, err := flushed.Collect()
	if err != nil {
		return results, err
	}
	return results, flushErr
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

// getECRAuth exchanges the caller's credentials for a registry authenticator.
// The account ID is no longer derived from ProxyEndpoint: it arrives on the
// enumerated resource as AccountRef.
func getECRAuth(ctx context.Context, client *ecr.Client) (authn.Authenticator, error) {
	resp, err := client.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return nil, fmt.Errorf("GetAuthorizationToken: %w", err)
	}
	if len(resp.AuthorizationData) == 0 {
		return nil, fmt.Errorf("no authorization data returned")
	}

	decoded, err := base64.StdEncoding.DecodeString(valStr(resp.AuthorizationData[0].AuthorizationToken))
	if err != nil {
		return nil, fmt.Errorf("decoding auth token: %w", err)
	}

	// Token format: "AWS:<password>"
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("unexpected auth token format")
	}

	return authn.FromConfig(authn.AuthConfig{
		Username: parts[0],
		Password: parts[1],
	}), nil
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

// --- Shared functions ---

// layerScanTarget is the per-image metadata every file extracted from that image
// inherits. It replaces threading seven positional strings into extractLayer.
type layerScanTarget struct {
	arn          string
	resourceType string
	region       string
	accountID    string
	// imageRef identifies the image within its repository and prefixes every
	// scan label, so findings from two images of one repository stay distinct.
	imageRef string
}

func pullAndExtract(img ecrImage, extractDir string, extractToFS, failOnError bool) ([]output.ScanInput, error) {
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
	target := layerScanTarget{
		arn:          img.ARN,
		resourceType: "AWS::ECR::Repository",
		region:       img.Region,
		accountID:    img.AccountID,
		imageRef:     img.ref(),
	}
	if img.IsPublic {
		target.resourceType = "AWS::ECR::PublicRepository"
	}
	if target.arn == "" {
		target.arn = fmt.Sprintf("arn:aws:ecr:%s:%s:repository/%s", img.Region, img.AccountID, img.RepoName)
	}

	for i, layer := range layers {
		rc, err := layer.Uncompressed()
		if err != nil {
			if failOnError {
				return nil, fmt.Errorf("read layer %d of %s: %w", i, img.RepoName, err)
			}
			slog.Warn("failed to read layer", "layer", i, "error", err)
			continue
		}

		inputs, err := extractLayer(rc, target, extractDir, extractToFS, i)
		_ = rc.Close()
		if err != nil {
			if failOnError {
				return nil, fmt.Errorf("extract layer %d of %s: %w", i, img.RepoName, err)
			}
			slog.Warn("failed to extract layer", "layer", i, "error", err)
			continue
		}
		scanInputs = append(scanInputs, inputs...)
	}

	return scanInputs, nil
}

func extractLayer(r io.Reader, target layerScanTarget, extractDir string, extractToFS bool, layerIdx int) ([]output.ScanInput, error) {
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

		scanInputs = append(scanInputs, output.ScanInput{
			Content:      content,
			ResourceID:   target.arn,
			ResourceType: target.resourceType,
			Region:       target.region,
			AccountID:    target.accountID,
			Platform:     "aws",
			Label:        fmt.Sprintf("%s:layer%d/%s", target.imageRef, layerIdx, hdr.Name),
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
