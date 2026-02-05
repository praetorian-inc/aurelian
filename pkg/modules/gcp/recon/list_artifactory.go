package recon

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/utils"
	"google.golang.org/api/artifactregistry/v1"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/option"
)

func init() {
	plugin.Register(&GCPListArtifactoryModule{})
}

// GCPListArtifactoryModule lists all Artifact Registry repositories and container images in a GCP project
type GCPListArtifactoryModule struct{}

func (m *GCPListArtifactoryModule) ID() string {
	return "artifactory-list"
}

func (m *GCPListArtifactoryModule) Name() string {
	return "GCP List Artifactory"
}

func (m *GCPListArtifactoryModule) Description() string {
	return "List all Artifact Registry repositories and container images in a GCP project."
}

func (m *GCPListArtifactoryModule) Platform() plugin.Platform {
	return plugin.PlatformGCP
}

func (m *GCPListArtifactoryModule) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *GCPListArtifactoryModule) OpsecLevel() string {
	return "moderate"
}

func (m *GCPListArtifactoryModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *GCPListArtifactoryModule) References() []string {
	return []string{}
}

func (m *GCPListArtifactoryModule) Parameters() []plugin.Parameter {
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

func (m *GCPListArtifactoryModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
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
	}

	// Create resource manager service to get project info
	resourceManagerService, err := cloudresourcemanager.NewService(cfg.Context, clientOptions...)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource manager service: %w", err)
	}

	// Get project info
	project, err := resourceManagerService.Projects.Get(projectID).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get project %s: %w", projectID, err)
	}

	gcpProject := &output.CloudResource{
		Platform:     "gcp",
		ResourceType: "cloudresourcemanager.googleapis.com/Project",
		ResourceID:   fmt.Sprintf("projects/%s", project.ProjectId),
		AccountRef:   fmt.Sprintf("%s/%s", project.Parent.Type, project.Parent.Id),
		DisplayName:  project.Name,
		Properties: map[string]any{
			"projectNumber":  strconv.FormatInt(project.ProjectNumber, 10),
			"lifecycleState": project.LifecycleState,
			"parentType":     project.Parent.Type,
			"parentId":       project.Parent.Id,
			"labels":         project.Labels,
		},
	}

	// Create artifact registry service
	artifactService, err := artifactregistry.NewService(cfg.Context, clientOptions...)
	if err != nil {
		return nil, utils.HandleGcpError(err, "failed to create artifact registry service")
	}

	// List all locations for the project
	locationsParent := fmt.Sprintf("projects/%s", projectID)
	locationsResp, err := artifactService.Projects.Locations.List(locationsParent).Do()
	if err != nil {
		return nil, utils.HandleGcpError(err, "failed to list locations")
	}

	// Collect all results
	var results []plugin.Result
	var mu sync.Mutex
	sem := make(chan struct{}, 10) // Limit concurrency
	var wg sync.WaitGroup

	// Process repositories in each location concurrently
	for _, location := range locationsResp.Locations {
		wg.Add(1)
		sem <- struct{}{}
		go func(locationName string) {
			defer wg.Done()
			defer func() { <-sem }()

			parent := fmt.Sprintf("projects/%s/locations/%s", projectID, locationName)
			listReq := artifactService.Projects.Locations.Repositories.List(parent)

			err := listReq.Pages(context.Background(), func(page *artifactregistry.ListRepositoriesResponse) error {
				for _, repo := range page.Repositories {
					// Create repository resource
					gcpRepo := &output.CloudResource{
						Platform:     "gcp",
						ResourceType: "artifactregistry.googleapis.com/Repository",
						ResourceID:   repo.Name,
						AccountRef:   projectID,
						DisplayName:  repo.Name,
						Properties:   postProcessRepository(repo),
					}
					slog.Debug("Found GCP Artifact Registry repository", "repository", gcpRepo.DisplayName)

					mu.Lock()
					results = append(results, plugin.Result{
						Data:     gcpRepo,
						Metadata: map[string]any{
							"module":   "artifactory-list",
							"platform": "gcp",
							"type":     "repository",
						},
					})
					mu.Unlock()

					// List images in this repository
					imageResults := listContainerImages(cfg.Context, artifactService, projectID, repo.Name)
					mu.Lock()
					results = append(results, imageResults...)
					mu.Unlock()
				}
				return nil
			})
			if handledErr := utils.HandleGcpError(err, "failed to list repositories in location"); handledErr != nil {
				slog.Error("error listing repositories", "error", handledErr, "location", locationName)
			}
		}(extractLocationName(location.Name))
	}
	wg.Wait()

	// Prepend project info
	allResults := []plugin.Result{
		{
			Data:     gcpProject,
			Metadata: map[string]any{
				"module":   "artifactory-list",
				"platform": "gcp",
				"type":     "project",
			},
		},
	}
	allResults = append(allResults, results...)

	return allResults, nil
}

// listContainerImages lists all container images in a repository
func listContainerImages(ctx context.Context, artifactService *artifactregistry.Service, projectID, repoName string) []plugin.Result {
	var results []plugin.Result

	// List Docker images
	listReq := artifactService.Projects.Locations.Repositories.DockerImages.List(repoName)
	err := listReq.Pages(ctx, func(page *artifactregistry.ListDockerImagesResponse) error {
		for _, image := range page.DockerImages {
			gcpImage := &output.CloudResource{
				Platform:     "gcp",
				ResourceType: "artifactregistry.googleapis.com/DockerImage",
				ResourceID:   image.Name,
				AccountRef:   projectID,
				DisplayName:  image.Name,
				Properties:   postProcessDockerImage(image),
			}
			slog.Debug("Found GCP container image", "image", gcpImage.DisplayName)

			results = append(results, plugin.Result{
				Data:     gcpImage,
				Metadata: map[string]any{
					"module":   "artifactory-list",
					"platform": "gcp",
					"type":     "container_image",
				},
			})
		}
		return nil
	})
	if handledErr := utils.HandleGcpError(err, "failed to list Docker images"); handledErr != nil {
		slog.Error("error listing container images", "error", handledErr, "repository", repoName)
	}

	return results
}

// postProcessRepository extracts relevant properties from a repository
func postProcessRepository(repo *artifactregistry.Repository) map[string]any {
	properties := map[string]any{
		"name":        repo.Name,
		"format":      repo.Format,
		"description": repo.Description,
		"createTime":  repo.CreateTime,
		"updateTime":  repo.UpdateTime,
		"labels":      repo.Labels,
	}

	if repo.MavenConfig != nil {
		properties["mavenConfig"] = map[string]any{
			"allowSnapshotOverwrites": repo.MavenConfig.AllowSnapshotOverwrites,
			"versionPolicy":           repo.MavenConfig.VersionPolicy,
		}
	}

	return properties
}

// postProcessDockerImage extracts relevant properties from a Docker image
func postProcessDockerImage(image *artifactregistry.DockerImage) map[string]any {
	properties := map[string]any{
		"name":       image.Name,
		"uri":        image.Uri,
		"tags":       image.Tags,
		"imageSizeBytes": image.ImageSizeBytes,
		"uploadTime": image.UploadTime,
		"updateTime": image.UpdateTime,
	}

	if image.BuildTime != "" {
		properties["buildTime"] = image.BuildTime
	}

	return properties
}

// extractLocationName extracts the location name from a full location path
// e.g., "projects/my-project/locations/us-central1" -> "us-central1"
func extractLocationName(fullPath string) string {
	parts := strings.Split(fullPath, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return fullPath
}
