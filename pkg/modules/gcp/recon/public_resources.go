package recon

import (
	"log/slog"

	"github.com/praetorian-inc/aurelian/pkg/gcp/enrichment"
	"github.com/praetorian-inc/aurelian/pkg/gcp/enumeration"
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
	return supportedInputTypes
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
		return out.Wait()
	}

	resolver := hierarchy.NewResolver(c.GCPCommonRecon)
	input := hierarchy.HierarchyResolverInput{
		OrgIDs:     c.OrgID,
		FolderIDs:  c.FolderID,
		ProjectIDs: c.ProjectID,
	}
	hierarchyStream := pipeline.From(input)
	resolved := pipeline.New[output.GCPResource]()
	pipeline.Pipe(hierarchyStream, resolver.Resolve, resolved)

	projects := pipeline.New[string]()
	pipeline.Pipe(resolved, filterProjects, projects)

	enumerator := enumeration.NewEnumerator(c.GCPCommonRecon).ForTypes(requestedTypes)
	listed := pipeline.New[output.GCPResource]()
	pipeline.Pipe(projects, enumerator.ListForProject, listed)

	enricher := enrichment.NewGCPEnricher(c.GCPCommonRecon)
	enriched := pipeline.New[output.GCPResource]()
	pipeline.Pipe(listed, enricher.Enrich, enriched)

	evaluator := publicaccess.AccessEvaluator{}
	pipeline.Pipe(enriched, evaluator.Evaluate, out)

	return out.Wait()
}

// filterProjects extracts project IDs from the hierarchy stream, discarding
// non-project resources.
func filterProjects(res output.GCPResource, p *pipeline.P[string]) error {
	if res.ResourceType == "projects" {
		p.Send(res.ProjectID)
	}
	return nil
}
