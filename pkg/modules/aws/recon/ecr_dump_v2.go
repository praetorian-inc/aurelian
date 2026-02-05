package recon

import (
	"archive/tar"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudcontrol"
	cctypes "github.com/aws/aws-sdk-go-v2/service/cloudcontrol/types"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/aws/aws-sdk-go-v2/service/ecrpublic"
	ecrpublictypes "github.com/aws/aws-sdk-go-v2/service/ecrpublic/types"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/client"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/types"
	"golang.org/x/sync/errgroup"
)

// ECRDumpV2 is the V2 implementation using plain Go patterns
// instead of janus-framework chains.
type ECRDumpV2 struct {
	Profile       string
	Regions       []string
	OutputDir     string
	MaxImages     int
	IncludePublic bool

	// Internal state
	config              aws.Config
	cloudControlClients map[string]*cloudcontrol.Client
	ecrClients          map[string]*ecr.Client
	ecrPublicClient     *ecrpublic.Client
}

// NewECRDumpV2 creates a new ECR dump scanner with sensible defaults.
func NewECRDumpV2(profile string, regions []string) *ECRDumpV2 {
	return &ECRDumpV2{
		Profile:       profile,
		Regions:       regions,
		OutputDir:     "/tmp/ecr-dump",
		MaxImages:     100,
		IncludePublic: true,
	}
}

// Run executes the ECR dump workflow.
// Returns the extracted files as NpInput objects for NoseyParker scanning.
func (e *ECRDumpV2) Run(ctx context.Context) ([]types.NpInput, error) {
	// 1. Initialize AWS clients
	if err := e.initialize(ctx); err != nil {
		return nil, fmt.Errorf("initialization failed: %w", err)
	}

	// 2. Create channels for streaming
	repoCh := make(chan *types.EnrichedResourceDescription, 100)
	imageCh := make(chan imageInfo, 100)
	resultCh := make(chan types.NpInput, 100)

	// 3. Start repository enumeration in background
	var enumErr error
	var enumWg sync.WaitGroup
	enumWg.Add(1)
	go func() {
		defer enumWg.Done()
		defer close(repoCh)
		enumErr = e.enumerateRepositories(ctx, repoCh)
	}()

	// 4. Start image listing in background
	var listErr error
	var listWg sync.WaitGroup
	listWg.Add(1)
	go func() {
		defer listWg.Done()
		defer close(imageCh)
		listErr = e.listImages(ctx, repoCh, imageCh)
	}()

	// 5. Start result collection in background
	var results []types.NpInput
	var collectWg sync.WaitGroup
	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		for result := range resultCh {
			results = append(results, result)
		}
	}()

	// 6. Process images with bounded concurrency
	procErr := e.processImages(ctx, imageCh, resultCh)

	// 7. Close result channel after processing completes
	close(resultCh)

	// 8. Wait for all goroutines to finish
	enumWg.Wait()
	listWg.Wait()
	collectWg.Wait()

	// 9. Check for errors
	if enumErr != nil {
		return nil, fmt.Errorf("enumeration failed: %w", enumErr)
	}
	if listErr != nil {
		return nil, fmt.Errorf("listing failed: %w", listErr)
	}
	if procErr != nil {
		return nil, fmt.Errorf("processing failed: %w", procErr)
	}

	return results, nil
}

// imageInfo contains information about an ECR image to process
type imageInfo struct {
	RepositoryName string
	ImageURI       string
	ImageTag       string
	ImageDigest    string
	Region         string
	AccountID      string
	IsPublic       bool
}

// initialize sets up AWS clients for all regions.
func (e *ECRDumpV2) initialize(ctx context.Context) error {
	opts := e.defaultCacheOptions()

	// Load base AWS config
	cfg, err := helpers.GetAWSCfg(e.Regions[0], e.Profile, opts, "moderate")
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}
	e.config = cfg

	// Create CloudControl clients for each region
	e.cloudControlClients = make(map[string]*cloudcontrol.Client)
	e.ecrClients = make(map[string]*ecr.Client)

	for _, region := range e.Regions {
		regionCfg, err := helpers.GetAWSCfg(region, e.Profile, opts, "moderate")
		if err != nil {
			return fmt.Errorf("failed to load AWS config for region %s: %w", region, err)
		}
		e.cloudControlClients[region] = cloudcontrol.NewFromConfig(regionCfg)
		e.ecrClients[region] = ecr.NewFromConfig(regionCfg)
	}

	// Create public ECR client (always us-east-1)
	if e.IncludePublic {
		publicCfg, err := helpers.GetAWSCfg("us-east-1", e.Profile, opts, "moderate")
		if err != nil {
			return fmt.Errorf("failed to load AWS config for public ECR: %w", err)
		}
		e.ecrPublicClient = ecrpublic.NewFromConfig(publicCfg)
	}

	return nil
}

// defaultCacheOptions returns the default cache options required by GetAWSCfg.
func (e *ECRDumpV2) defaultCacheOptions() []*types.Option {
	// Use same pattern as find_secrets_v2.go - return nil if no custom options needed
	return nil
}

// enumerateRepositories streams ECR repositories to the provided channel.
func (e *ECRDumpV2) enumerateRepositories(ctx context.Context, repoCh chan<- *types.EnrichedResourceDescription) error {
	var wg sync.WaitGroup
	errCh := make(chan error, len(e.Regions)*2) // *2 for public + private

	// Enumerate private repositories
	for _, region := range e.Regions {
		wg.Add(1)
		go func(reg string) {
			defer wg.Done()
			if err := e.listResourcesInRegion(ctx, "AWS::ECR::Repository", reg, repoCh); err != nil {
				errCh <- err
			}
		}(region)
	}

	// Enumerate public repositories (only in us-east-1)
	if e.IncludePublic {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := e.listResourcesInRegion(ctx, "AWS::ECR::PublicRepository", "us-east-1", repoCh); err != nil {
				errCh <- err
			}
		}()
	}

	// Wait for all enumerations to complete
	wg.Wait()
	close(errCh)

	// Collect any errors
	var errs []error
	for err := range errCh {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("enumeration encountered %d errors: %v", len(errs), errs[0])
	}

	return nil
}

// listResourcesInRegion lists all resources of a given type in a region.
func (e *ECRDumpV2) listResourcesInRegion(ctx context.Context, resourceType, region string, repoCh chan<- *types.EnrichedResourceDescription) error {
	slog.Debug("Listing ECR repositories", "type", resourceType, "region", region)

	cc := e.cloudControlClients[region]

	// Get account ID
	accountID, err := helpers.GetAccountId(e.config)
	if err != nil {
		return fmt.Errorf("failed to get account ID: %w", err)
	}

	// Paginate through all resources
	paginator := cloudcontrol.NewListResourcesPaginator(cc, &cloudcontrol.ListResourcesInput{
		TypeName:   aws.String(resourceType),
		MaxResults: aws.Int32(100),
	})

	for paginator.HasMorePages() {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		res, err := paginator.NextPage(ctx)
		if err != nil {
			// Handle known error types gracefully
			if e.shouldSkipError(resourceType, region, err) {
				return nil
			}
			return fmt.Errorf("failed to list resources of type %s in region %s: %w", resourceType, region, err)
		}

		// Convert and send each resource
		for _, resource := range res.ResourceDescriptions {
			erd := e.resourceDescriptionToERD(resource, resourceType, accountID, region)

			// Send to channel (non-blocking with context check)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case repoCh <- erd:
			}
		}
	}

	return nil
}

// resourceDescriptionToERD converts CloudControl resource description to EnrichedResourceDescription.
func (e *ECRDumpV2) resourceDescriptionToERD(resource cctypes.ResourceDescription, rType, accountID, region string) *types.EnrichedResourceDescription {
	erd := types.NewEnrichedResourceDescription(
		*resource.Identifier,
		rType,
		region,
		accountID,
		*resource.Properties,
	)
	return &erd
}

// shouldSkipError determines if an error should cause enumeration to skip this resource type/region.
func (e *ECRDumpV2) shouldSkipError(resourceType, region string, err error) bool {
	errMsg := err.Error()

	skipErrors := []string{
		"TypeNotFoundException",
		"UnsupportedActionException",
		"is not authorized to perform",
		"AccessDeniedException",
	}

	for _, skipErr := range skipErrors {
		if strings.Contains(errMsg, skipErr) {
			slog.Debug("Resource type not available", "type", resourceType, "region", region, "error", errMsg)
			return true
		}
	}

	return false
}

// listImages lists the latest image for each repository and sends to imageCh.
func (e *ECRDumpV2) listImages(ctx context.Context, repoCh <-chan *types.EnrichedResourceDescription, imageCh chan<- imageInfo) error {
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(25) // Bounded concurrency

	for repo := range repoCh {
		repo := repo // Capture loop variable
		g.Go(func() error {
			return e.listImagesForRepository(gCtx, repo, imageCh)
		})
	}

	return g.Wait()
}

// listImagesForRepository lists images for a single repository.
func (e *ECRDumpV2) listImagesForRepository(ctx context.Context, repo *types.EnrichedResourceDescription, imageCh chan<- imageInfo) error {
	isPublic := repo.TypeName == "AWS::ECR::PublicRepository"

	if isPublic {
		return e.listPublicImages(ctx, repo, imageCh)
	}
	return e.listPrivateImages(ctx, repo, imageCh)
}

// listPrivateImages lists images for a private ECR repository.
func (e *ECRDumpV2) listPrivateImages(ctx context.Context, repo *types.EnrichedResourceDescription, imageCh chan<- imageInfo) error {
	ecrClient := e.ecrClients[repo.Region]

	input := &ecr.DescribeImagesInput{
		RepositoryName: aws.String(repo.Identifier),
		MaxResults:     aws.Int32(1000),
	}

	var latest *ecrtypes.ImageDetail

	// Find the latest image
	for {
		result, err := ecrClient.DescribeImages(ctx, input)
		if err != nil {
			slog.Warn("Failed to describe images", "repository", repo.Identifier, "error", err)
			return nil // Don't fail entire scan
		}

		for _, img := range result.ImageDetails {
			if latest == nil || img.ImagePushedAt.After(*latest.ImagePushedAt) {
				latest = &img
			}
		}

		if result.NextToken == nil {
			break
		}
		input.NextToken = result.NextToken
	}

	if latest == nil {
		slog.Debug("No images found", "repository", repo.Identifier)
		return nil
	}

	// Build image URI
	registry := fmt.Sprintf("%s.dkr.ecr.%s.amazonaws.com", repo.AccountId, repo.Region)
	var uri, tag string
	if len(latest.ImageTags) > 0 {
		tag = latest.ImageTags[0]
		uri = fmt.Sprintf("%s/%s:%s", registry, repo.Identifier, tag)
	} else if latest.ImageDigest != nil {
		tag = *latest.ImageDigest
		uri = fmt.Sprintf("%s/%s@%s", registry, repo.Identifier, *latest.ImageDigest)
	} else {
		return nil
	}

	info := imageInfo{
		RepositoryName: repo.Identifier,
		ImageURI:       uri,
		ImageTag:       tag,
		Region:         repo.Region,
		AccountID:      repo.AccountId,
		IsPublic:       false,
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case imageCh <- info:
	}

	return nil
}

// listPublicImages lists images for a public ECR repository.
func (e *ECRDumpV2) listPublicImages(ctx context.Context, repo *types.EnrichedResourceDescription, imageCh chan<- imageInfo) error {
	if e.ecrPublicClient == nil {
		return nil
	}

	// Parse repository name from properties
	var props struct {
		RepositoryName string `json:"RepositoryName"`
	}
	propsJSON, ok := repo.Properties.(string)
	if !ok {
		slog.Warn("Properties is not a string", "repository", repo.Identifier)
		return nil
	}
	if err := json.Unmarshal([]byte(propsJSON), &props); err != nil {
		slog.Warn("Failed to parse repository properties", "repository", repo.Identifier, "error", err)
		return nil
	}

	input := &ecrpublic.DescribeImagesInput{
		RepositoryName: aws.String(props.RepositoryName),
		MaxResults:     aws.Int32(1000),
	}

	result, err := e.ecrPublicClient.DescribeImages(ctx, input)
	if err != nil {
		slog.Warn("Failed to describe public images", "repository", props.RepositoryName, "error", err)
		return nil
	}

	if len(result.ImageDetails) == 0 {
		slog.Debug("No public images found", "repository", props.RepositoryName)
		return nil
	}

	// Find latest image
	var latest *ecrpublictypes.ImageDetail
	for i := range result.ImageDetails {
		img := &result.ImageDetails[i]
		if latest == nil || (img.ImagePushedAt != nil && img.ImagePushedAt.After(*latest.ImagePushedAt)) {
			latest = img
		}
	}

	// Build image URI
	var uri, tag string
	if len(latest.ImageTags) > 0 {
		tag = latest.ImageTags[0]
		uri = fmt.Sprintf("public.ecr.aws/%s:%s", props.RepositoryName, tag)
	} else if latest.ImageDigest != nil {
		tag = *latest.ImageDigest
		uri = fmt.Sprintf("public.ecr.aws/%s@%s", props.RepositoryName, *latest.ImageDigest)
	} else {
		return nil
	}

	info := imageInfo{
		RepositoryName: props.RepositoryName,
		ImageURI:       uri,
		ImageTag:       tag,
		Region:         "us-east-1",
		AccountID:      repo.AccountId,
		IsPublic:       true,
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case imageCh <- info:
	}

	return nil
}

// processImages processes images with bounded concurrency using errgroup.
func (e *ECRDumpV2) processImages(ctx context.Context, imageCh <-chan imageInfo, resultCh chan<- types.NpInput) error {
	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(25) // Bounded concurrency

	imageCount := 0
	var countMu sync.Mutex

	for img := range imageCh {
		img := img // Capture loop variable

		// Check image limit
		countMu.Lock()
		if e.MaxImages > 0 && imageCount >= e.MaxImages {
			countMu.Unlock()
			break
		}
		imageCount++
		countMu.Unlock()

		g.Go(func() error {
			return e.processImage(gCtx, img, resultCh)
		})
	}

	return g.Wait()
}

// processImage processes a single image: authenticate, pull, extract, and send files.
func (e *ECRDumpV2) processImage(ctx context.Context, img imageInfo, resultCh chan<- types.NpInput) error {
	slog.Info("Processing image", "uri", img.ImageURI)

	// 1. Get authentication
	authConfig, err := e.getAuthConfig(ctx, img)
	if err != nil {
		return fmt.Errorf("failed to get auth for %s: %w", img.ImageURI, err)
	}

	// 2. Create Docker client
	dockerClient, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create docker client: %w", err)
	}
	defer dockerClient.Close()

	// 3. Pull image
	pullOpts := image.PullOptions{
		RegistryAuth: encodeAuthConfig(authConfig),
	}

	pullReader, err := dockerClient.ImagePull(ctx, img.ImageURI, pullOpts)
	if err != nil {
		return fmt.Errorf("failed to pull image %s: %w", img.ImageURI, err)
	}
	defer pullReader.Close()

	// Consume pull output
	io.Copy(io.Discard, pullReader)

	// 4. Get image ID
	inspect, err := dockerClient.ImageInspect(ctx, img.ImageURI)
	if err != nil {
		return fmt.Errorf("failed to inspect image %s: %w", img.ImageURI, err)
	}

	imageID := inspect.ID

	// 5. Save image to tar
	saveReader, err := dockerClient.ImageSave(ctx, []string{imageID})
	if err != nil {
		return fmt.Errorf("failed to save image %s: %w", img.ImageURI, err)
	}
	defer saveReader.Close()

	// 6. Extract tar contents and send files
	if err := e.extractAndSendFiles(ctx, saveReader, img, resultCh); err != nil {
		return fmt.Errorf("failed to extract files from %s: %w", img.ImageURI, err)
	}

	// 7. Clean up image
	if _, err := dockerClient.ImageRemove(ctx, imageID, image.RemoveOptions{Force: true}); err != nil {
		slog.Warn("Failed to remove image", "id", imageID, "error", err)
	}

	return nil
}

// getAuthConfig gets ECR authentication for an image.
func (e *ECRDumpV2) getAuthConfig(ctx context.Context, img imageInfo) (registry.AuthConfig, error) {
	if img.IsPublic {
		return e.getPublicAuthConfig(ctx)
	}
	return e.getPrivateAuthConfig(ctx, img.Region, img.AccountID)
}

// getPrivateAuthConfig gets authentication for private ECR.
func (e *ECRDumpV2) getPrivateAuthConfig(ctx context.Context, region, accountID string) (registry.AuthConfig, error) {
	ecrClient := e.ecrClients[region]

	tokenOutput, err := ecrClient.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return registry.AuthConfig{}, fmt.Errorf("failed to get authorization token: %w", err)
	}

	if len(tokenOutput.AuthorizationData) == 0 {
		return registry.AuthConfig{}, fmt.Errorf("no authorization data returned")
	}

	token := tokenOutput.AuthorizationData[0].AuthorizationToken
	decoded, err := base64.StdEncoding.DecodeString(*token)
	if err != nil {
		return registry.AuthConfig{}, fmt.Errorf("failed to decode token: %w", err)
	}

	// Token format is "AWS:password"
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return registry.AuthConfig{}, fmt.Errorf("invalid token format")
	}

	return registry.AuthConfig{
		Username:      parts[0],
		Password:      parts[1],
		ServerAddress: fmt.Sprintf("https://%s.dkr.ecr.%s.amazonaws.com", accountID, region),
	}, nil
}

// getPublicAuthConfig gets authentication for public ECR.
func (e *ECRDumpV2) getPublicAuthConfig(ctx context.Context) (registry.AuthConfig, error) {
	tokenOutput, err := e.ecrPublicClient.GetAuthorizationToken(ctx, &ecrpublic.GetAuthorizationTokenInput{})
	if err != nil {
		return registry.AuthConfig{}, fmt.Errorf("failed to get public authorization token: %w", err)
	}

	token := tokenOutput.AuthorizationData.AuthorizationToken
	decoded, err := base64.StdEncoding.DecodeString(*token)
	if err != nil {
		return registry.AuthConfig{}, fmt.Errorf("failed to decode public token: %w", err)
	}

	return registry.AuthConfig{
		Username:      "AWS",
		Password:      string(decoded),
		ServerAddress: "https://public.ecr.aws",
	}, nil
}

// encodeAuthConfig encodes auth config to base64 JSON for Docker API.
func encodeAuthConfig(authConfig registry.AuthConfig) string {
	authJSON, _ := json.Marshal(authConfig)
	return base64.URLEncoding.EncodeToString(authJSON)
}

// extractAndSendFiles extracts files from a tar stream and sends them as NpInput.
func (e *ECRDumpV2) extractAndSendFiles(ctx context.Context, tarReader io.Reader, img imageInfo, resultCh chan<- types.NpInput) error {
	tr := tar.NewReader(tarReader)

	for {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar: %w", err)
		}

		// Only process regular files
		if header.Typeflag != tar.TypeReg {
			continue
		}

		// Skip very large files (>10MB)
		if header.Size > 10*1024*1024 {
			continue
		}

		// Read file contents
		content, err := io.ReadAll(tr)
		if err != nil {
			slog.Warn("Failed to read file", "name", header.Name, "error", err)
			continue
		}

		// Send to result channel
		npInput := types.NpInput{
			Content: string(content),
			Provenance: types.NpProvenance{
				Platform:     "aws",
				ResourceType: "ecr-image",
				ResourceID:   fmt.Sprintf("%s/%s/%s", img.RepositoryName, img.ImageTag, header.Name),
				Region:       img.Region,
				AccountID:    img.AccountID,
			},
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case resultCh <- npInput:
		}
	}

	return nil
}
