package secrets

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/utils"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/artifactregistry/v1"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/option"
)

func init() {
	plugin.Register(&ScanArtifactoryModule{})
}

// ScanArtifactoryModule scans GCP Artifact Registry for secrets
type ScanArtifactoryModule struct{}

func (m *ScanArtifactoryModule) ID() string {
	return "artifactory-secrets"
}

func (m *ScanArtifactoryModule) Name() string {
	return "GCP Scan Artifactory Secrets"
}

func (m *ScanArtifactoryModule) Description() string {
	return "List all Artifact Registry repositories and container images in a GCP project and scan them for secrets."
}

func (m *ScanArtifactoryModule) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *ScanArtifactoryModule) Category() plugin.Category {
	return plugin.CategorySecrets
}

func (m *ScanArtifactoryModule) OpsecLevel() string {
	return "moderate"
}

func (m *ScanArtifactoryModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *ScanArtifactoryModule) References() []string {
	return []string{}
}

func (m *ScanArtifactoryModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "project",
			Description: "GCP project ID",
			Type:        "string",
			Required:    true,
		},
		{
			Name:        "creds-file",
			Description: "Path to GCP service account credentials JSON file",
			Type:        "string",
		},
	}
}

func (m *ScanArtifactoryModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Get project parameter
	projectID, ok := cfg.Args["project"].(string)
	if !ok || projectID == "" {
		return nil, fmt.Errorf("project parameter is required")
	}

	// Get optional credentials file parameter
	credsFile, _ := cfg.Args["creds-file"].(string)

	// Setup GCP client options
	var clientOptions []option.ClientOption
	if credsFile != "" {
		clientOptions = append(clientOptions, option.WithCredentialsFile(credsFile))
	} else {
		// Use Application Default Credentials
		creds, err := google.FindDefaultCredentials(context.Background())
		if err != nil {
			return nil, fmt.Errorf("failed to find default credentials: %w", err)
		}
		clientOptions = append(clientOptions, option.WithCredentials(creds))
	}

	ctx := context.Background()

	// Initialize services
	resourceManagerService, err := cloudresourcemanager.NewService(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource manager service: %w", err)
	}

	artifactService, err := artifactregistry.NewService(ctx, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create artifact registry service: %w", err)
	}

	// Get project info
	project, err := resourceManagerService.Projects.Get(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get project %s: %w", projectID, err)
	}

	slog.Info("Scanning GCP project", "project", projectID, "name", project.Name)

	// List all repositories across all locations
	repositories, err := m.listAllRepositories(ctx, artifactService, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to list repositories: %w", err)
	}

	slog.Info("Found repositories", "count", len(repositories))

	// List all Docker images across all repositories
	var allImages []*artifactregistry.DockerImage
	for _, repo := range repositories {
		// Only process Docker format repositories
		format, _ := repo.Properties["format"].(string)
		if format != "DOCKER" {
			continue
		}

		images, err := m.listContainerImages(ctx, artifactService, repo.ResourceID)
		if err != nil {
			slog.Error("Failed to list images", "repository", repo.ResourceID, "error", err)
			continue
		}
		allImages = append(allImages, images...)
	}

	slog.Info("Found container images", "count", len(allImages))

	// Build result data
	imageData := make([]map[string]any, 0, len(allImages))
	for _, image := range allImages {
		imageData = append(imageData, map[string]any{
			"name":           image.Name,
			"uri":            image.Uri,
			"tags":           image.Tags,
			"mediaType":      image.MediaType,
			"buildTime":      image.BuildTime,
			"updateTime":     image.UpdateTime,
			"imageSizeBytes": image.ImageSizeBytes,
		})
	}

	data := map[string]any{
		"project":      projectID,
		"repositories": len(repositories),
		"images":       imageData,
		"total_images": len(allImages),
	}

	return []plugin.Result{
		{
			Data: data,
			Metadata: map[string]any{
				"module":      "artifactory-secrets",
				"platform":    "gcp",
				"opsec_level": "moderate",
			},
		},
	}, nil
}

// listAllRepositories lists all Artifact Registry repositories across all locations
func (m *ScanArtifactoryModule) listAllRepositories(ctx context.Context, service *artifactregistry.Service, projectID string) ([]repositoryInfo, error) {
	// List all locations
	locationsParent := fmt.Sprintf("projects/%s", projectID)
	locationsReq := service.Projects.Locations.List(locationsParent)
	locations, err := locationsReq.Do()
	if err != nil {
		return nil, utils.HandleGcpError(err, "failed to list locations")
	}

	// Process locations in parallel
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var allRepos []repositoryInfo

	for _, location := range locations.Locations {
		wg.Add(1)
		sem <- struct{}{}
		go func(locationName string) {
			defer wg.Done()
			defer func() { <-sem }()

			repos, err := m.listRepositoriesInLocation(service, projectID, locationName)
			if err != nil {
				slog.Error("Failed to process location", "location", locationName, "error", err)
				return
			}

			mu.Lock()
			allRepos = append(allRepos, repos...)
			mu.Unlock()
		}(location.Name)
	}
	wg.Wait()

	return allRepos, nil
}

// repositoryInfo holds basic repository information
type repositoryInfo struct {
	ResourceID string
	Name       string
	AccountRef string
	Properties map[string]any
}

// listRepositoriesInLocation lists repositories in a specific location
func (m *ScanArtifactoryModule) listRepositoriesInLocation(service *artifactregistry.Service, projectID, locationName string) ([]repositoryInfo, error) {
	// Extract location ID from full path (projects/PROJECT/locations/LOCATION)
	locationParts := strings.Split(locationName, "/")
	if len(locationParts) < 4 {
		return nil, fmt.Errorf("invalid location name format: %s", locationName)
	}
	locationID := locationParts[3]

	// List repositories in this location
	reposParent := fmt.Sprintf("projects/%s/locations/%s", projectID, locationID)
	reposReq := service.Projects.Locations.Repositories.List(reposParent)

	repos, err := reposReq.Do()
	if err != nil {
		return nil, utils.HandleGcpError(err, "failed to list repositories")
	}

	var result []repositoryInfo
	for _, repo := range repos.Repositories {
		result = append(result, repositoryInfo{
			ResourceID: repo.Name,
			Name:       repo.Name,
			AccountRef: projectID,
			Properties: map[string]any{
				"name":        repo.Name,
				"format":      repo.Format,
				"description": repo.Description,
				"labels":      repo.Labels,
				"createTime":  repo.CreateTime,
				"updateTime":  repo.UpdateTime,
				"sizeBytes":   repo.SizeBytes,
			},
		})
	}

	return result, nil
}

// listContainerImages lists all Docker images in a repository
func (m *ScanArtifactoryModule) listContainerImages(ctx context.Context, service *artifactregistry.Service, repositoryID string) ([]*artifactregistry.DockerImage, error) {
	imagesReq := service.Projects.Locations.Repositories.DockerImages.List(repositoryID)
	images, err := imagesReq.Do()
	if err != nil {
		return nil, utils.HandleGcpError(err, fmt.Sprintf("failed to list docker images in repository %s", repositoryID))
	}

	return images.DockerImages, nil
}
