package enumeration

import (
	"context"
	"fmt"
	"log/slog"

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

	parent := "projects/" + projectID + "/locations/-"
	err = svc.Projects.Locations.Repositories.List(parent).Pages(context.Background(), func(resp *artifactregistry.ListRepositoriesResponse) error {
		for _, repo := range resp.Repositories {
			r := output.NewGCPResource(projectID, "artifactregistry.googleapis.com/Repository", repo.Name)
			r.DisplayName = repo.Name
			r.Labels = repo.Labels
			r.Properties = map[string]any{
				"format":    repo.Format,
				"mode":      repo.Mode,
				"sizeBytes": repo.SizeBytes,
			}
			out.Send(r)

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
			slog.Debug("skipping artifact registry", "project", projectID, "reason", err)
			return nil
		}
		return fmt.Errorf("listing artifact registry repositories: %w", err)
	}
	return nil
}

func (l *ArtifactRegistryLister) listDockerImages(svc *artifactregistry.Service, projectID, repoName string, out *pipeline.P[output.GCPResource]) error {
	return svc.Projects.Locations.Repositories.DockerImages.List(repoName).Pages(context.Background(), func(resp *artifactregistry.ListDockerImagesResponse) error {
		for _, img := range resp.DockerImages {
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
		return nil
	})
}

func (l *ArtifactRegistryLister) ResourceType() string { return "artifactregistry.googleapis.com/Repository" }
