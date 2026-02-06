package containers

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/praetorian-inc/aurelian/pkg/links/gcp/common"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/artifactregistry/v1"
	"google.golang.org/api/option"
)

// FILE INFO:
// GcpRepositoryInfoLink - get info of a single Artifact Registry repository, Process(repositoryName string); needs project and location
// GcpRepositoryListLink - list all repositories in a project, Process(resource tab.GCPResource)
// GcpContainerImageListLink - list all images in a repository, Process(resource tab.GCPResource)
// GcpContainerImageSecretsLink - scan container image for secrets, Process(input tab.GCPResource)

type GcpRepositoryInfoLink struct {
	*plugin.BaseLink
	artifactService *artifactregistry.Service
	ProjectId       string
	Location        string
	ClientOptions   []option.ClientOption
}

// creates a link to get info of a single Artifact Registry repository
func NewGcpRepositoryInfoLink(args map[string]any) *GcpRepositoryInfoLink {
	return &GcpRepositoryInfoLink{
		BaseLink: plugin.NewBaseLink("gcp-repository-info", args),
	}
}

func (g *GcpRepositoryInfoLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("project", "GCP project ID", plugin.WithRequired()),
		plugin.NewParam[string]("location", "GCP location", plugin.WithRequired()),
		plugin.NewParam[string]("credentials", "Path to GCP credentials file"),
	}
}

func (g *GcpRepositoryInfoLink) Process(ctx context.Context, input any) ([]any, error) {
	// Initialize service on first call
	if g.artifactService == nil {
		if creds, ok := g.Arg("credentials").(string); ok && creds != "" {
			g.ClientOptions = []option.ClientOption{option.WithCredentialsFile(creds)}
		}
		var err error
		g.artifactService, err = artifactregistry.NewService(ctx, g.ClientOptions...)
		if err != nil {
			return nil, fmt.Errorf("failed to create artifact registry service: %w", err)
		}

		projectId := g.ArgString("project", "")
		if projectId == "" {
			return nil, fmt.Errorf("project parameter is required")
		}
		g.ProjectId = projectId

		location := g.ArgString("location", "")
		if location == "" {
			return nil, fmt.Errorf("location parameter is required")
		}
		g.Location = location
	}

	repositoryName, ok := input.(string)
	if !ok {
		return nil, fmt.Errorf("expected string input (repository name), got %T", input)
	}

	repoPath := fmt.Sprintf("projects/%s/locations/%s/repositories/%s", g.ProjectId, g.Location, repositoryName)
	repo, err := g.artifactService.Projects.Locations.Repositories.Get(repoPath).Do()
	if err != nil {
		return nil, common.HandleGcpError(err, "failed to get repository")
	}
	gcpRepo, err := tab.NewGCPResource(
		repo.Name,   // resource name
		g.ProjectId, // accountRef (project ID)
		"artifactregistry.googleapis.com/Repository", // resource type
		linkPostProcessRepository(repo),              // properties
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCP repository resource: %w", err)
	}
	gcpRepo.DisplayName = repo.Name
	return []any{gcpRepo}, nil
}

type GcpRepositoryListLink struct {
	*plugin.BaseLink
	artifactService *artifactregistry.Service
	ClientOptions   []option.ClientOption
}

// creates a link to list all repositories in a project
func NewGcpRepositoryListLink(args map[string]any) *GcpRepositoryListLink {
	return &GcpRepositoryListLink{
		BaseLink: plugin.NewBaseLink("gcp-repository-list", args),
	}
}

func (g *GcpRepositoryListLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("project", "GCP project ID", plugin.WithRequired()),
		plugin.NewParam[string]("credentials", "Path to GCP credentials file"),
	}
}

func (g *GcpRepositoryListLink) Process(ctx context.Context, input any) ([]any, error) {
	// Initialize service on first call
	if g.artifactService == nil {
		if creds, ok := g.Arg("credentials").(string); ok && creds != "" {
			g.ClientOptions = []option.ClientOption{option.WithCredentialsFile(creds)}
		}
		var err error
		g.artifactService, err = artifactregistry.NewService(ctx, g.ClientOptions...)
		if err != nil {
			return nil, fmt.Errorf("failed to create artifact registry service: %w", err)
		}
	}

	resource, ok := input.(tab.GCPResource)
	if !ok {
		return nil, fmt.Errorf("expected tab.GCPResource input, got %T", input)
	}

	if resource.ResourceType != tab.GCPResourceProject {
		return nil, nil
	}
	projectId := resource.Name
	locationsParent := fmt.Sprintf("projects/%s", projectId)
	locationsReq := g.artifactService.Projects.Locations.List(locationsParent)
	locations, err := locationsReq.Do()
	if err != nil {
		return nil, common.HandleGcpError(err, "failed to list locations")
	}

	var results []any
	var mu sync.Mutex
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	for _, location := range locations.Locations {
		wg.Add(1)
		sem <- struct{}{}
		go func(locationName string) {
			defer wg.Done()
			defer func() { <-sem }()
			repos, err := g.processLocation(projectId, locationName)
			if err != nil {
				slog.Error("Failed to process location", "location", locationName, "error", err)
				return
			}
			mu.Lock()
			results = append(results, repos...)
			mu.Unlock()
		}(location.Name)
	}
	wg.Wait()
	return results, nil
}

func (g *GcpRepositoryListLink) processLocation(projectId, locationName string) ([]any, error) {
	// Extract location ID from full path (projects/PROJECT/locations/LOCATION)
	locationParts := strings.Split(locationName, "/")
	if len(locationParts) < 4 {
		return nil, fmt.Errorf("invalid location name format: %s", locationName)
	}
	locationId := locationParts[3]

	// List repositories in this location
	reposParent := fmt.Sprintf("projects/%s/locations/%s", projectId, locationId)
	reposReq := g.artifactService.Projects.Locations.Repositories.List(reposParent)

	repos, err := reposReq.Do()
	if err != nil {
		return nil, common.HandleGcpError(err, "failed to list repositories")
	}

	var results []any
	for _, repo := range repos.Repositories {
		gcpRepo, err := tab.NewGCPResource(
			repo.Name, // resource name
			projectId, // accountRef (project ID)
			"artifactregistry.googleapis.com/Repository", // resource type
			linkPostProcessRepository(repo),              // properties
		)
		if err != nil {
			slog.Error("Failed to create GCP repository resource", "error", err, "repository", repo.Name)
			continue
		}
		gcpRepo.DisplayName = repo.Name
		results = append(results, gcpRepo)
	}
	return results, nil
}

type GcpContainerImageListLink struct {
	*plugin.BaseLink
	artifactService *artifactregistry.Service
	ClientOptions   []option.ClientOption
}

// creates a link to list all images in a repository
func NewGcpContainerImageListLink(args map[string]any) *GcpContainerImageListLink {
	return &GcpContainerImageListLink{
		BaseLink: plugin.NewBaseLink("gcp-container-image-list", args),
	}
}

func (g *GcpContainerImageListLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("credentials", "Path to GCP credentials file"),
	}
}

func (g *GcpContainerImageListLink) Process(ctx context.Context, input any) ([]any, error) {
	// Initialize service on first call
	if g.artifactService == nil {
		if creds, ok := g.Arg("credentials").(string); ok && creds != "" {
			g.ClientOptions = []option.ClientOption{option.WithCredentialsFile(creds)}
		}
		var err error
		g.artifactService, err = artifactregistry.NewService(ctx, g.ClientOptions...)
		if err != nil {
			return nil, fmt.Errorf("failed to create artifact registry service: %w", err)
		}
	}

	resource, ok := input.(tab.GCPResource)
	if !ok {
		return nil, fmt.Errorf("expected tab.GCPResource input, got %T", input)
	}

	if resource.ResourceType != "artifactregistry.googleapis.com/Repository" {
		return nil, nil
	}
	format, _ := resource.Properties["format"].(string)
	if format != "DOCKER" {
		return nil, nil
	}
	imagesReq := g.artifactService.Projects.Locations.Repositories.DockerImages.List(resource.Name)
	images, err := imagesReq.Do()
	if err != nil {
		return nil, common.HandleGcpError(err, fmt.Sprintf("failed to list docker images in repository %s", resource.Name))
	}

	var results []any
	for _, image := range images.DockerImages {
		gcpImage, err := tab.NewGCPResource(
			image.Name,          // resource name
			resource.AccountRef, // accountRef (project ID)
			"artifactregistry.googleapis.com/DockerImage", // resource type
			linkPostProcessContainerImage(image),          // properties
		)
		if err != nil {
			slog.Error("Failed to create GCP container image resource", "error", err, "image", image.Name)
			continue
		}
		gcpImage.DisplayName = image.Name
		results = append(results, gcpImage)
	}
	return results, nil
}

type GcpContainerImageSecretsLink struct {
	*plugin.BaseLink
	artifactService *artifactregistry.Service
	ClientOptions   []option.ClientOption
}

// creates a link to scan container image for secrets
func NewGcpContainerImageSecretsLink(args map[string]any) *GcpContainerImageSecretsLink {
	return &GcpContainerImageSecretsLink{
		BaseLink: plugin.NewBaseLink("gcp-container-image-secrets", args),
	}
}

func (g *GcpContainerImageSecretsLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("credentials", "Path to GCP credentials file"),
	}
}

func (g *GcpContainerImageSecretsLink) Process(ctx context.Context, input any) ([]any, error) {
	// Initialize service on first call
	if g.artifactService == nil {
		if creds, ok := g.Arg("credentials").(string); ok && creds != "" {
			g.ClientOptions = []option.ClientOption{option.WithCredentialsFile(creds)}
		}
		var err error
		g.artifactService, err = artifactregistry.NewService(ctx, g.ClientOptions...)
		if err != nil {
			return nil, fmt.Errorf("failed to create artifact registry service: %w", err)
		}
	}

	resource, ok := input.(tab.GCPResource)
	if !ok {
		return nil, fmt.Errorf("expected tab.GCPResource input, got %T", input)
	}

	if resource.ResourceType != "artifactregistry.googleapis.com/DockerImage" {
		return nil, nil
	}
	image, err := g.artifactService.Projects.Locations.Repositories.DockerImages.Get(resource.Name).Do()
	if err != nil {
		return nil, common.HandleGcpError(err, "failed to get docker image for secrets extraction")
	}

	// Create a map with image information for downstream processing
	dockerImage := map[string]any{
		"uri":     image.Uri,
		"address": g.extractRegistryURL(image.Uri),
	}

	return []any{dockerImage}, nil
}

func (g *GcpContainerImageSecretsLink) extractRegistryURL(imageURI string) string {
	parts := strings.Split(imageURI, "/")
	if len(parts) > 0 {
		return parts[0]
	}
	return "gcr.io" // technically not correct because gcr is different from artifactreg
}

// ------------------------------------------------------------------------------------------------
// helper functions

func linkPostProcessRepository(repo *artifactregistry.Repository) map[string]any {
	properties := map[string]any{
		"name":        repo.Name,
		"format":      repo.Format,
		"description": repo.Description,
"labels":      repo.Labels,
		"createTime":  repo.CreateTime,
		"updateTime":  repo.UpdateTime,
		"sizeBytes":   repo.SizeBytes,
	}

	return properties
}

func linkPostProcessContainerImage(image *artifactregistry.DockerImage) map[string]any {
	properties := map[string]any{
		"name":           image.Name,
		"tags":           image.Tags,
		"mediaType":      image.MediaType,
		"buildTime":      image.BuildTime,
		"updateTime":     image.UpdateTime,
		"imageSizeBytes": image.ImageSizeBytes,
	}

	if image.Uri != "" {
		properties["publicURL"] = image.Uri
	}

	return properties
}
