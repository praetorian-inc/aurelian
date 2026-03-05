package recon

import (
	"context"
	"log/slog"
	"slices"

	"golang.org/x/sync/errgroup"

	"github.com/praetorian-inc/aurelian/pkg/gcp/applications"
	"github.com/praetorian-inc/aurelian/pkg/gcp/compute"
	"github.com/praetorian-inc/aurelian/pkg/gcp/containers"
	"github.com/praetorian-inc/aurelian/pkg/gcp/enrichment"
	"github.com/praetorian-inc/aurelian/pkg/gcp/firebase"
	"github.com/praetorian-inc/aurelian/pkg/gcp/hierarchy"
	"github.com/praetorian-inc/aurelian/pkg/gcp/networking"
	"github.com/praetorian-inc/aurelian/pkg/gcp/publicaccess"
	"github.com/praetorian-inc/aurelian/pkg/gcp/storage"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"google.golang.org/api/option"
)

func init() {
	plugin.Register(&GCPListAllResourcesModule{})
}

// GCPListAllConfig holds parameters for the GCP list-all module.
type GCPListAllConfig struct {
	plugin.GCPCommonRecon
}

// GCPListAllResourcesModule enumerates all GCP resources across projects.
type GCPListAllResourcesModule struct {
	GCPListAllConfig
}

func (m *GCPListAllResourcesModule) ID() string                { return "list-all" }
func (m *GCPListAllResourcesModule) Name() string              { return "GCP List All Resources" }
func (m *GCPListAllResourcesModule) Platform() plugin.Platform { return plugin.PlatformGCP }
func (m *GCPListAllResourcesModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *GCPListAllResourcesModule) OpsecLevel() string        { return "moderate" }
func (m *GCPListAllResourcesModule) Authors() []string         { return []string{"Praetorian"} }

func (m *GCPListAllResourcesModule) Description() string {
	return "List GCP resources across organization, folder, or project scope. " +
		"Supports filtering by resource type and evaluates public/anonymous access."
}

func (m *GCPListAllResourcesModule) References() []string {
	return []string{"https://cloud.google.com/apis/docs/overview"}
}

func (m *GCPListAllResourcesModule) SupportedResourceTypes() []string {
	return allResourceTypes()
}

func (m *GCPListAllResourcesModule) Parameters() any {
	return &m.GCPListAllConfig
}

func (m *GCPListAllResourcesModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.GCPListAllConfig

	requestedTypes, err := resolveResourceTypes(c.ResourceType)
	if err != nil {
		return err
	}

	// Stage 1: Resolve hierarchy (blocking). Hierarchy resources are collected
	// and emitted before the pipeline stages start.
	resolver := hierarchy.NewResolver(c.GCPCommonRecon)
	hierarchyOut := pipeline.New[output.GCPResource]()

	var projects []string
	var resolveErr error
	go func() {
		defer hierarchyOut.Close()
		projects, resolveErr = resolver.ResolveProjects(
			context.Background(),
			c.OrgID, c.FolderID, c.ProjectID,
			hierarchyOut,
		)
	}()

	for r := range hierarchyOut.Range() {
		out.Send(r)
	}
	if resolveErr != nil {
		return resolveErr
	}

	if !shouldFanOutToResources(requestedTypes) || len(projects) == 0 {
		return nil
	}

	// Stage 2: List resources per project
	listed := pipeline.New[output.GCPResource]()
	projectStream := pipeline.From(projects...)
	pipeline.Pipe(projectStream, listForProject(c.GCPCommonRecon, requestedTypes), listed)

	// Stage 3: Enrich
	enricher := enrichment.NewGCPEnricher(c.GCPCommonRecon)
	enriched := pipeline.New[output.GCPResource]()
	pipeline.Pipe(listed, enricher.Enrich, enriched)

	// Stage 4: Evaluate and emit
	evaluator := publicaccess.AccessEvaluator{}
	pipeline.Pipe(enriched, evaluator.Evaluate, out)

	return out.Wait()
}

type resourceLister func(projectID string, out *pipeline.P[output.GCPResource]) error

func listForProject(opts plugin.GCPCommonRecon, requestedTypes []string) func(string, *pipeline.P[output.GCPResource]) error {
	return func(projectID string, out *pipeline.P[output.GCPResource]) error {
		listers := buildListers(opts.ClientOptions, requestedTypes)
		if len(listers) == 0 {
			return nil
		}

		g := errgroup.Group{}
		g.SetLimit(opts.Concurrency)

		for name, lister := range listers {
			g.Go(func() error {
				if err := lister(projectID, out); err != nil {
					slog.Warn("resource listing failed",
						"type", name,
						"project", projectID,
						"error", err)
				}
				return nil // Log and continue, don't propagate
			})
		}
		return g.Wait()
	}
}

func buildListers(co []option.ClientOption, requestedTypes []string) map[string]resourceLister {
	listers := make(map[string]resourceLister)

	includes := func(canonical string) bool {
		return slices.Contains(requestedTypes, canonical)
	}

	if includes("storage.googleapis.com/Bucket") {
		listers["storage.googleapis.com/Bucket"] = storage.NewBucketLister(co).List
	}
	if includes("sqladmin.googleapis.com/Instance") {
		listers["sqladmin.googleapis.com/Instance"] = storage.NewSQLInstanceLister(co).List
	}
	if includes("compute.googleapis.com/Instance") {
		listers["compute.googleapis.com/Instance"] = compute.NewInstanceLister(co).List
	}
	if includes("compute.googleapis.com/ForwardingRule") || includes("compute.googleapis.com/GlobalForwardingRule") {
		listers["compute.googleapis.com/ForwardingRule"] = networking.NewForwardingRuleLister(co).List
	}
	if includes("compute.googleapis.com/Address") {
		listers["compute.googleapis.com/Address"] = networking.NewAddressLister(co).List
	}
	if includes("dns.googleapis.com/ManagedZone") {
		listers["dns.googleapis.com/ManagedZone"] = networking.NewDNSZoneLister(co).List
	}
	if includes("cloudfunctions.googleapis.com/Function") {
		listers["cloudfunctions.googleapis.com/Function"] = applications.NewFunctionLister(co).List
	}
	if includes("run.googleapis.com/Service") {
		listers["run.googleapis.com/Service"] = applications.NewCloudRunLister(co).List
	}
	if includes("appengine.googleapis.com/Service") {
		listers["appengine.googleapis.com/Service"] = applications.NewAppEngineLister(co).List
	}
	if includes("artifactregistry.googleapis.com/Repository") || includes("artifactregistry.googleapis.com/DockerImage") {
		listers["artifactregistry.googleapis.com/Repository"] = containers.NewArtifactRegistryLister(co).List
	}
	if includes("firebasehosting.googleapis.com/Site") {
		listers["firebasehosting.googleapis.com/Site"] = firebase.NewHostingLister(co).List
	}

	return listers
}
