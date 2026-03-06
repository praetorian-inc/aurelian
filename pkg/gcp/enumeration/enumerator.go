package enumeration

import (
	"log/slog"
	"slices"

	"golang.org/x/sync/errgroup"

	"github.com/praetorian-inc/aurelian/pkg/gcp/applications"
	"github.com/praetorian-inc/aurelian/pkg/gcp/compute"
	"github.com/praetorian-inc/aurelian/pkg/gcp/containers"
	"github.com/praetorian-inc/aurelian/pkg/gcp/firebase"
	"github.com/praetorian-inc/aurelian/pkg/gcp/networking"
	"github.com/praetorian-inc/aurelian/pkg/gcp/storage"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"google.golang.org/api/option"
)

// ResourceLister lists resources of a specific type within a project.
type ResourceLister interface {
	ResourceType() string
	List(projectID string, out *pipeline.P[output.GCPResource]) error
}

// Enumerator dispatches resource listing to registered type-specific listers.
type Enumerator struct {
	listers     []ResourceLister
	concurrency int
}

// NewEnumerator creates an Enumerator with all built-in listers registered.
func NewEnumerator(opts plugin.GCPCommonRecon) *Enumerator {
	co := opts.ClientOptions
	return &Enumerator{
		listers: buildDefaultListers(co),
		concurrency: opts.Concurrency,
	}
}

// ForTypes returns a new Enumerator filtered to only the given resource types.
func (e *Enumerator) ForTypes(types []string) *Enumerator {
	var filtered []ResourceLister
	for _, l := range e.listers {
		if slices.Contains(types, l.ResourceType()) {
			filtered = append(filtered, l)
		}
	}
	return &Enumerator{listers: filtered, concurrency: e.concurrency}
}

// ListForProject lists all registered resource types within a single project.
func (e *Enumerator) ListForProject(projectID string, out *pipeline.P[output.GCPResource]) error {
	g := errgroup.Group{}
	g.SetLimit(e.concurrency)

	for _, lister := range e.listers {
		g.Go(func() error {
			if err := lister.List(projectID, out); err != nil {
				slog.Warn("resource listing failed",
					"type", lister.ResourceType(),
					"project", projectID,
					"error", err)
			}
			return nil
		})
	}
	return g.Wait()
}

func buildDefaultListers(co []option.ClientOption) []ResourceLister {
	return []ResourceLister{
		storage.NewBucketLister(co),
		storage.NewSQLInstanceLister(co),
		compute.NewInstanceLister(co),
		networking.NewForwardingRuleLister(co),
		networking.NewAddressLister(co),
		networking.NewDNSZoneLister(co),
		applications.NewFunctionLister(co),
		applications.NewCloudRunLister(co),
		applications.NewAppEngineLister(co),
		containers.NewArtifactRegistryLister(co),
		firebase.NewHostingLister(co),
	}
}
