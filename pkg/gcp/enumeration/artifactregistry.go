package enumeration

import (
	"context"
	"fmt"
	"log/slog"

	"golang.org/x/sync/errgroup"
	"google.golang.org/api/artifactregistry/v1"
	"google.golang.org/api/option"

	"github.com/praetorian-inc/aurelian/pkg/gcp/gcperrors"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// ArtifactRegistryLister enumerates Artifact Registry repositories and Docker images in a GCP project.
type ArtifactRegistryLister struct {
	clientOptions []option.ClientOption
}

// NewArtifactRegistryLister creates an ArtifactRegistryLister with the given client options.
func NewArtifactRegistryLister(clientOptions []option.ClientOption) *ArtifactRegistryLister {
	return &ArtifactRegistryLister{clientOptions: clientOptions}
}

// List enumerates all Artifact Registry repositories and Docker images for the given project.
func (l *ArtifactRegistryLister) List(projectID string, out *pipeline.P[output.GCPResource]) error {
	svc, err := artifactregistry.NewService(context.Background(), l.clientOptions...)
	if err != nil {
		return fmt.Errorf("creating artifact registry client: %w", err)
	}

	var locations []string
	err = svc.Projects.Locations.List("projects/"+projectID).Pages(context.Background(), func(resp *artifactregistry.ListLocationsResponse) error {
		for _, loc := range resp.Locations {
			if loc.Name != "" {
				locations = append(locations, loc.Name)
			}
		}
		return nil
	})
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping artifact registry", "project", projectID, "reason", err)
			return nil
		}
		return fmt.Errorf("listing artifact registry locations: %w", err)
	}

	g := errgroup.Group{}
	g.SetLimit(10)
	for _, location := range locations {
		g.Go(func() error {
			return l.listRepositories(svc, projectID, location, out)
		})
	}
	return g.Wait()
}

func (l *ArtifactRegistryLister) listRepositories(svc *artifactregistry.Service, projectID, parent string, out *pipeline.P[output.GCPResource]) error {
	err := svc.Projects.Locations.Repositories.List(parent).Pages(context.Background(), func(resp *artifactregistry.ListRepositoriesResponse) error {
		for _, repo := range resp.Repositories {
			sendArtifactRepository(projectID, repo, out)

			// For DOCKER-format repos, also list Docker images.
			if repo.Format == "DOCKER" {
				if err := l.listDockerImages(svc, projectID, repo.Name, out); err != nil {
					if gcperrors.ShouldSkip(err) {
						slog.Debug("skipping docker images", "project", projectID, "repo", repo.Name, "reason", err)
						continue
					}
					return fmt.Errorf("listing docker images in %s: %w", repo.Name, err)
				}
			}
		}
		return nil
	})
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping artifact registry repositories", "project", projectID, "location", parent, "reason", err)
			return nil
		}
		return fmt.Errorf("listing artifact registry repositories in %s: %w", parent, err)
	}
	return nil
}

func (l *ArtifactRegistryLister) listDockerImages(svc *artifactregistry.Service, projectID, repoName string, out *pipeline.P[output.GCPResource]) error {
	return svc.Projects.Locations.Repositories.DockerImages.List(repoName).Pages(context.Background(), func(resp *artifactregistry.ListDockerImagesResponse) error {
		for _, img := range resp.DockerImages {
			sendDockerImage(projectID, img, out)
		}
		return nil
	})
}

func (l *ArtifactRegistryLister) ListByResourceID(input ResourceIDInput, out *pipeline.P[output.GCPResource]) error {
	svc, err := artifactregistry.NewService(context.Background(), l.clientOptions...)
	if err != nil {
		return fmt.Errorf("creating artifact registry client: %w", err)
	}
	name := fullGCPResourceName(input.ProjectID, input.ResourceID)
	if _, ok := pathSegment(name, "locations"); !ok {
		return newResourceIDError(input.ResourceType, input.ResourceID, "a full path containing locations/{location}/repositories/{repository}")
	}
	if _, ok := pathSegment(name, "repositories"); !ok {
		return newResourceIDError(input.ResourceType, input.ResourceID, "a full path containing locations/{location}/repositories/{repository}")
	}

	if input.ResourceType == "artifactregistry.googleapis.com/DockerImage" {
		img, err := svc.Projects.Locations.Repositories.DockerImages.Get(name).Do()
		if err != nil {
			if gcperrors.ShouldSkip(err) {
				slog.Debug("skipping docker image", "project", input.ProjectID, "image", name, "reason", err)
				return nil
			}
			return fmt.Errorf("getting docker image %s: %w", name, err)
		}
		sendDockerImage(input.ProjectID, img, out)
		return nil
	}

	repo, err := svc.Projects.Locations.Repositories.Get(name).Do()
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping artifact registry repository", "project", input.ProjectID, "repository", name, "reason", err)
			return nil
		}
		return fmt.Errorf("getting artifact registry repository %s: %w", name, err)
	}
	sendArtifactRepository(input.ProjectID, repo, out)
	return nil
}

func (l *ArtifactRegistryLister) ResourceTypes() []string {
	return []string{"artifactregistry.googleapis.com/Repository", "artifactregistry.googleapis.com/DockerImage"}
}

func sendArtifactRepository(projectID string, repo *artifactregistry.Repository, out *pipeline.P[output.GCPResource]) {
	r := output.NewGCPResource(projectID, "artifactregistry.googleapis.com/Repository", repo.Name)
	r.DisplayName = repo.Name
	r.Labels = repo.Labels
	r.Properties = map[string]any{
		"format":    repo.Format,
		"mode":      repo.Mode,
		"sizeBytes": repo.SizeBytes,
	}
	out.Send(r)
}

func sendDockerImage(projectID string, img *artifactregistry.DockerImage, out *pipeline.P[output.GCPResource]) {
	r := output.NewGCPResource(projectID, "artifactregistry.googleapis.com/DockerImage", img.Name)
	r.DisplayName = img.Uri
	r.URLs = []string{img.Uri}
	r.Properties = map[string]any{
		"tags":       img.Tags,
		"uploadTime": img.UploadTime,
		"mediaType":  img.MediaType,
	}
	out.Send(r)
}
