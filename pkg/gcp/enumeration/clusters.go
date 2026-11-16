package enumeration

import (
	"context"
	"fmt"
	"log/slog"

	container "google.golang.org/api/container/v1"
	"google.golang.org/api/option"

	"github.com/praetorian-inc/aurelian/pkg/gcp/gcperrors"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
)

// ClusterLister enumerates GKE (Kubernetes Engine) clusters in a GCP project.
type ClusterLister struct {
	clientOptions []option.ClientOption
}

// NewClusterLister creates a ClusterLister with the given client options.
func NewClusterLister(clientOptions []option.ClientOption) *ClusterLister {
	return &ClusterLister{clientOptions: clientOptions}
}

// List enumerates all GKE clusters across all locations for the given project.
// The container API returns every cluster in a single call when the location
// wildcard "-" is used, so no pagination loop is needed.
func (l *ClusterLister) List(projectID string, out *pipeline.P[output.GCPResource]) error {
	svc, err := container.NewService(context.Background(), l.clientOptions...)
	if err != nil {
		return fmt.Errorf("creating container client: %w", err)
	}

	parent := "projects/" + projectID + "/locations/-"
	resp, err := svc.Projects.Locations.Clusters.List(parent).Do()
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping gke clusters", "project", projectID, "reason", err)
			return nil
		}
		return fmt.Errorf("listing gke clusters: %w", err)
	}

	if len(resp.MissingZones) > 0 {
		slog.Warn("gke clusters may be incomplete; some zones were unreachable", "project", projectID, "missingZones", resp.MissingZones)
	}

	for _, cluster := range resp.Clusters {
		sendCluster(projectID, cluster, out)
	}
	return nil
}

func (l *ClusterLister) ListByResourceID(input ResourceIDInput, out *pipeline.P[output.GCPResource]) error {
	location, ok := pathSegment(input.ResourceID, "locations")
	if !ok {
		return newResourceIDError(input.ResourceType, input.ResourceID, "a full path containing locations/{location}/clusters/{name}")
	}
	name, ok := pathSegment(input.ResourceID, "clusters")
	if !ok {
		return newResourceIDError(input.ResourceType, input.ResourceID, "a full path containing locations/{location}/clusters/{name}")
	}

	svc, err := container.NewService(context.Background(), l.clientOptions...)
	if err != nil {
		return fmt.Errorf("creating container client: %w", err)
	}

	clusterName := fmt.Sprintf("projects/%s/locations/%s/clusters/%s", input.ProjectID, location, name)
	cluster, err := svc.Projects.Locations.Clusters.Get(clusterName).Do()
	if err != nil {
		if gcperrors.ShouldSkip(err) {
			slog.Debug("skipping gke cluster", "project", input.ProjectID, "resource", clusterName, "reason", err)
			return nil
		}
		return fmt.Errorf("getting gke cluster %s: %w", clusterName, err)
	}
	sendCluster(input.ProjectID, cluster, out)
	return nil
}

func (l *ClusterLister) ResourceTypes() []string {
	return []string{"container.googleapis.com/Cluster"}
}

func sendCluster(projectID string, cluster *container.Cluster, out *pipeline.P[output.GCPResource]) {
	resourceID := relativeGCPResourceID(cluster.SelfLink)
	if resourceID == "" {
		resourceID = fmt.Sprintf("projects/%s/locations/%s/clusters/%s", projectID, cluster.Location, cluster.Name)
	}

	r := output.NewGCPResource(projectID, "container.googleapis.com/Cluster", resourceID)
	r.DisplayName = cluster.Name
	r.Location = cluster.Location
	r.Labels = cluster.ResourceLabels

	if cluster.Endpoint != "" {
		r.IPs = []string{cluster.Endpoint}
	}

	r.Properties = map[string]any{
		"status":               cluster.Status,
		"currentMasterVersion": cluster.CurrentMasterVersion,
		"endpoint":             cluster.Endpoint,
	}
	out.Send(r)
}
