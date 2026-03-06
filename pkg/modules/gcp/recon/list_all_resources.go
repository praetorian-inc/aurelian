package recon

import (
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
	return supportedInputTypes
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
	projects, err := resolver.ResolveAndEmit(c.OrgID, c.FolderID, c.ProjectID, out)
	if err != nil {
		return err
	}

	if !shouldFanOutToResources(requestedTypes) || len(projects) == 0 {
		return out.Wait()
	}

	// Stage 2: List resources per project
	enumerator := enumeration.NewEnumerator(c.GCPCommonRecon).ForTypes(requestedTypes)
	listed := pipeline.New[output.GCPResource]()
	projectStream := pipeline.From(projects...)
	pipeline.Pipe(projectStream, enumerator.ListForProject, listed)

	// Stage 3: Enrich
	enricher := enrichment.NewGCPEnricher(c.GCPCommonRecon)
	enriched := pipeline.New[output.GCPResource]()
	pipeline.Pipe(listed, enricher.Enrich, enriched)

	// Stage 4: Evaluate and emit
	evaluator := publicaccess.AccessEvaluator{}
	pipeline.Pipe(enriched, evaluator.Evaluate, out)

	return out.Wait()
}


