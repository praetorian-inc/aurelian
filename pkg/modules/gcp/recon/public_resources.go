package recon

import (
	"context"
	"log/slog"

	"golang.org/x/sync/errgroup"

	"github.com/praetorian-inc/aurelian/pkg/gcp/enrichment"
	"github.com/praetorian-inc/aurelian/pkg/gcp/hierarchy"
	"github.com/praetorian-inc/aurelian/pkg/gcp/publicaccess"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&GCPPublicResourcesModule{})
}

// GCPPublicResourcesConfig holds parameters for the GCP public-resources module.
type GCPPublicResourcesConfig struct {
	plugin.GCPCommonRecon
}

// GCPPublicResourcesModule enumerates GCP resources with public/anonymous access.
type GCPPublicResourcesModule struct {
	GCPPublicResourcesConfig
}

func (m *GCPPublicResourcesModule) ID() string                { return "public-resources" }
func (m *GCPPublicResourcesModule) Name() string              { return "GCP Public Resources" }
func (m *GCPPublicResourcesModule) Platform() plugin.Platform { return plugin.PlatformGCP }
func (m *GCPPublicResourcesModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *GCPPublicResourcesModule) OpsecLevel() string        { return "moderate" }
func (m *GCPPublicResourcesModule) Authors() []string         { return []string{"Praetorian"} }

func (m *GCPPublicResourcesModule) Description() string {
	return "List GCP resources with public network exposure or anonymous access. " +
		"Focuses on resource types with meaningful public access indicators."
}

func (m *GCPPublicResourcesModule) References() []string {
	return []string{"https://cloud.google.com/apis/docs/overview"}
}

// publicResourceTypes are resource types with meaningful public access evaluation.
var publicResourceTypes = []string{
	"compute.googleapis.com/Instance",
	"compute.googleapis.com/ForwardingRule",
	"compute.googleapis.com/GlobalForwardingRule",
	"compute.googleapis.com/Address",
	"storage.googleapis.com/Bucket",
	"sqladmin.googleapis.com/Instance",
	"cloudfunctions.googleapis.com/Function",
	"run.googleapis.com/Service",
	"appengine.googleapis.com/Service",
	"firebasehosting.googleapis.com/Site",
}

func (m *GCPPublicResourcesModule) SupportedResourceTypes() []string {
	return publicResourceTypes
}

func (m *GCPPublicResourcesModule) Parameters() any {
	return &m.GCPPublicResourcesConfig
}

func (m *GCPPublicResourcesModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.GCPPublicResourcesConfig

	// Narrow requested types to those with public access evaluation.
	requestedTypes := filterResourceTypes(c.ResourceType, publicResourceTypes)
	if len(requestedTypes) == 0 {
		slog.Info("no supported resource types requested for public access evaluation")
		return nil
	}

	// Stage 1: Resolve hierarchy (blocking).
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

	if len(projects) == 0 {
		return nil
	}

	// Stage 2: List resources per project
	listed := pipeline.New[output.GCPResource]()
	projectStream := pipeline.From(projects...)
	pipeline.Pipe(projectStream, publicListForProject(c.GCPCommonRecon, requestedTypes), listed)

	// Stage 3: Enrich
	enricher := enrichment.NewGCPEnricher(c.GCPCommonRecon)
	enriched := pipeline.New[output.GCPResource]()
	pipeline.Pipe(listed, enricher.Enrich, enriched)

	// Stage 4: Evaluate and emit
	evaluator := publicaccess.AccessEvaluator{}
	pipeline.Pipe(enriched, evaluator.Evaluate, out)

	return out.Wait()
}

func publicListForProject(opts plugin.GCPCommonRecon, requestedTypes []string) func(string, *pipeline.P[output.GCPResource]) error {
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
				return nil
			})
		}
		return g.Wait()
	}
}
