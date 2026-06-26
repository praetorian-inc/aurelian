package enumeration

import (
	"fmt"
	"log/slog"
	"slices"

	"golang.org/x/sync/errgroup"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"google.golang.org/api/option"
)

// ResourceIDInput identifies a single GCP resource to fetch directly.
type ResourceIDInput struct {
	ProjectID    string
	ResourceType string
	ResourceID   string
}

// ResourceLister lists resources of one or more specific types within a project.
type ResourceLister interface {
	ResourceTypes() []string
	List(projectID string, out *pipeline.P[output.GCPResource]) error
	ListByResourceID(input ResourceIDInput, out *pipeline.P[output.GCPResource]) error
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
		listers:     buildDefaultListers(co),
		concurrency: opts.Concurrency,
	}
}

// ForTypes returns a new Enumerator filtered to only the given resource types.
func (e *Enumerator) ForTypes(types []string) *Enumerator {
	var filtered []ResourceLister
	for _, l := range e.listers {
		if resourceTypesOverlap(types, l.ResourceTypes()) {
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
					"types", lister.ResourceTypes(),
					"project", projectID,
					"error", err)
			}
			return nil
		})
	}
	return g.Wait()
}

// ListByResourceID fetches one resource by dispatching to the lister for input.ResourceType.
func (e *Enumerator) ListByResourceID(input ResourceIDInput, out *pipeline.P[output.GCPResource]) error {
	for _, lister := range e.listers {
		if slices.Contains(lister.ResourceTypes(), input.ResourceType) {
			return lister.ListByResourceID(input, out)
		}
	}
	return fmt.Errorf("unsupported GCP resource type %q", input.ResourceType)
}

func resourceTypesOverlap(requested, supported []string) bool {
	for _, t := range requested {
		if slices.Contains(supported, t) {
			return true
		}
	}
	return false
}

func buildDefaultListers(co []option.ClientOption) []ResourceLister {
	return []ResourceLister{
		NewBucketLister(co),
		NewSQLInstanceLister(co),
		NewInstanceLister(co),
		NewForwardingRuleLister(co),
		NewAddressLister(co),
		NewDNSZoneLister(co),
		NewFunctionLister(co),
		NewCloudRunLister(co),
		NewAppEngineLister(co),
		NewArtifactRegistryLister(co),
		NewHostingLister(co),
	}
}
