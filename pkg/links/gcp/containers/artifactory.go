package containers

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/docker/docker/api/types/registry"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	dockerTypes "github.com/praetorian-inc/janus-framework/pkg/types/docker"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/utils"
	tab "github.com/praetorian-inc/tabularium/pkg/model/model"
	"google.golang.org/api/artifactregistry/v1"
)

// FILE INFO:
// GcpRepositoryInfoLink - get info of a single Artifact Registry repository, Process(repositoryName string); needs project and location
// GcpRepositoryListLink - list all repositories in a project, Process(resource tab.GCPResource)
// GcpContainerImageListLink - list all images in a repository, Process(resource tab.GCPResource)
// GcpContainerImageSecretsLink - scan container image for secrets, Process(input tab.GCPResource)

type GcpRepositoryInfoLink struct {
	*base.GcpBaseLink
	artifactService *artifactregistry.Service
	ProjectId       string
	Location        string
}

// creates a link to get info of a single Artifact Registry repository
func NewGcpRepositoryInfoLink(configs ...cfg.Config) chain.Link {
	g := &GcpRepositoryInfoLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpRepositoryInfoLink) Params() []cfg.Param {
	params := append(g.GcpBaseLink.Params(),
		options.GcpProject(),
		cfg.NewParam[string]("location", "GCP location/region for Artifact Registry").WithDefault("us-central1").AsRequired(),
	)
	return params
}

func (g *GcpRepositoryInfoLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.artifactService, err = artifactregistry.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create artifact registry service: %w", err)
	}
	projectId, err := cfg.As[string](g.Arg("project"))
	if err != nil {
		return fmt.Errorf("failed to get project: %w", err)
	}
	g.ProjectId = projectId
	location, err := cfg.As[string](g.Arg("location"))
	if err != nil {
		return fmt.Errorf("failed to get location: %w", err)
	}
	g.Location = location
	return nil
}

func (g *GcpRepositoryInfoLink) Process(repositoryName string) error {
	repoPath := fmt.Sprintf("projects/%s/locations/%s/repositories/%s", g.ProjectId, g.Location, repositoryName)
	repo, err := g.artifactService.Projects.Locations.Repositories.Get(repoPath).Do()
	if err != nil {
		return utils.HandleGcpError(err, "failed to get repository")
	}
	gcpRepo, err := tab.NewGCPResource(
		repo.Name,   // resource name
		g.ProjectId, // accountRef (project ID)
		"artifactregistry.googleapis.com/Repository", // resource type
		linkPostProcessRepository(repo),              // properties
	)
	if err != nil {
		return fmt.Errorf("failed to create GCP repository resource: %w", err)
	}
	gcpRepo.DisplayName = repo.Name
	g.Send(gcpRepo)
	return nil
}

type GcpRepositoryListLink struct {
	*base.GcpBaseLink
	artifactService *artifactregistry.Service
}

// creates a link to list all repositories in a project
func NewGcpRepositoryListLink(configs ...cfg.Config) chain.Link {
	g := &GcpRepositoryListLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpRepositoryListLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.artifactService, err = artifactregistry.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create artifact registry service: %w", err)
	}
	return nil
}

func (g *GcpRepositoryListLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != tab.GCPResourceProject {
		return nil
	}
	projectId := resource.Name
	locationsParent := fmt.Sprintf("projects/%s", projectId)
	locationsReq := g.artifactService.Projects.Locations.List(locationsParent)
	locations, err := locationsReq.Do()
	if err != nil {
		return utils.HandleGcpError(err, "failed to list locations")
	}

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	for _, location := range locations.Locations {
		wg.Add(1)
		sem <- struct{}{}
		go func(locationName string) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := g.processLocation(projectId, locationName); err != nil {
				slog.Error("Failed to process location", "location", locationName, "error", err)
			}
		}(location.Name)
	}
	wg.Wait()
	return nil
}

func (g *GcpRepositoryListLink) processLocation(projectId, locationName string) error {
	// Extract location ID from full path (projects/PROJECT/locations/LOCATION)
	locationParts := strings.Split(locationName, "/")
	if len(locationParts) < 4 {
		return fmt.Errorf("invalid location name format: %s", locationName)
	}
	locationId := locationParts[3]

	// List repositories in this location
	reposParent := fmt.Sprintf("projects/%s/locations/%s", projectId, locationId)
	reposReq := g.artifactService.Projects.Locations.Repositories.List(reposParent)

	repos, err := reposReq.Do()
	if err != nil {
		return utils.HandleGcpError(err, "failed to list repositories")
	}

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
		g.Send(gcpRepo)
	}
	return nil
}

type GcpContainerImageListLink struct {
	*base.GcpBaseLink
	artifactService *artifactregistry.Service
}

// creates a link to list all images in a repository
func NewGcpContainerImageListLink(configs ...cfg.Config) chain.Link {
	g := &GcpContainerImageListLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpContainerImageListLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.artifactService, err = artifactregistry.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create artifact registry service: %w", err)
	}
	return nil
}

func (g *GcpContainerImageListLink) Process(resource tab.GCPResource) error {
	if resource.ResourceType != "artifactregistry.googleapis.com/Repository" {
		return nil
	}
	format, _ := resource.Properties["format"].(string)
	if format != "DOCKER" {
		return nil
	}
	imagesReq := g.artifactService.Projects.Locations.Repositories.DockerImages.List(resource.Name)
	images, err := imagesReq.Do()
	if err != nil {
		return utils.HandleGcpError(err, fmt.Sprintf("failed to list docker images in repository %s", resource.Name))
	}
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
		g.Send(gcpImage)
	}
	return nil
}

type GcpContainerImageSecretsLink struct {
	*base.GcpBaseLink
	artifactService *artifactregistry.Service
}

// creates a link to scan container image for secrets
func NewGcpContainerImageSecretsLink(configs ...cfg.Config) chain.Link {
	g := &GcpContainerImageSecretsLink{}
	g.GcpBaseLink = base.NewGcpBaseLink(g, configs...)
	return g
}

func (g *GcpContainerImageSecretsLink) Initialize() error {
	if err := g.GcpBaseLink.Initialize(); err != nil {
		return err
	}
	var err error
	g.artifactService, err = artifactregistry.NewService(context.Background(), g.ClientOptions...)
	if err != nil {
		return fmt.Errorf("failed to create artifact registry service: %w", err)
	}
	return nil
}

func (g *GcpContainerImageSecretsLink) Process(input tab.GCPResource) error {
	if input.ResourceType != "artifactregistry.googleapis.com/DockerImage" {
		return nil
	}
	image, err := g.artifactService.Projects.Locations.Repositories.DockerImages.Get(input.Name).Do()
	if err != nil {
		return utils.HandleGcpError(err, "failed to get docker image for secrets extraction")
	}
	dockerImage := dockerTypes.DockerImage{
		Image: image.Uri,
		AuthConfig: registry.AuthConfig{
			ServerAddress: g.extractRegistryURL(image.Uri),
		},
	}

	// send to Docker framework chain
	return g.Send(&dockerImage)
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
