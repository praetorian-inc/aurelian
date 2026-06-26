package recon

import (
	"fmt"
	"log/slog"
	"slices"

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
	"compute.googleapis.com/GlobalAddress",
	"storage.googleapis.com/Bucket",
	"sqladmin.googleapis.com/Instance",
	"cloudfunctions.googleapis.com/Function",
	"run.googleapis.com/Service",
	"appengine.googleapis.com/Service",
	"firebasehosting.googleapis.com/Site",
}

func (m *GCPPublicResourcesModule) SupportedResourceTypes() []string {
	return append(slices.Clone(supportedInputTypes), publicResourceTypes...)
}

func (m *GCPPublicResourcesModule) Parameters() any {
	return &m.GCPPublicResourcesConfig
}

func (m *GCPPublicResourcesModule) Run(_ plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.GCPPublicResourcesConfig

	var listed *pipeline.P[output.GCPResource]
	var err error
	if len(c.ResourceID) > 0 {
		listed, err = m.listByResourceID(c)
		if err != nil {
			return err
		}
	} else {
		listed = m.listByHierarchy(c)
		if listed == nil {
			return nil
		}
	}

	enricher := enrichment.NewGCPEnricher(c.GCPCommonRecon)
	enriched := pipeline.New[output.GCPResource]()
	pipeline.Pipe(listed, enricher.Enrich, enriched)

	evaluator := publicaccess.AccessEvaluator{}
	pipeline.Pipe(enriched, evaluator.Evaluate, out)

	return out.Wait()
}

func (m *GCPPublicResourcesModule) listByHierarchy(c GCPPublicResourcesConfig) *pipeline.P[output.GCPResource] {
	// Narrow requested types to those with public access evaluation.
	requestedTypes := filterResourceTypes(c.ResourceType, publicResourceTypes)
	if len(requestedTypes) == 0 {
		slog.Info("no supported resource types requested for public access evaluation")
		return nil
	}

	var projects *pipeline.P[string]
	if len(c.OrgID) == 0 && len(c.FolderID) == 0 {
		projects = pipeline.From(c.ProjectID...)
	} else {
		resolver := hierarchy.NewResolver(c.GCPCommonRecon)
		input := hierarchy.HierarchyResolverInput{
			OrgIDs:     c.OrgID,
			FolderIDs:  c.FolderID,
			ProjectIDs: c.ProjectID,
		}
		hierarchyStream := pipeline.From(input)
		resolved := pipeline.New[output.GCPResource]()
		pipeline.Pipe(hierarchyStream, resolver.Resolve, resolved)

		projects = pipeline.New[string]()
		pipeline.Pipe(resolved, filterProjects, projects)
	}

	enumerator := enumeration.NewEnumerator(c.GCPCommonRecon).ForTypes(requestedTypes)
	listed := pipeline.New[output.GCPResource]()
	pipeline.Pipe(projects, enumerator.ListForProject, listed)
	return listed
}

func (m *GCPPublicResourcesModule) listByResourceID(c GCPPublicResourcesConfig) (*pipeline.P[output.GCPResource], error) {
	if len(c.ProjectID) != 1 {
		return nil, fmt.Errorf("direct GCP public resource scanning requires exactly one --project-id")
	}
	if len(c.ResourceType) != 1 || c.ResourceType[0] == "all" {
		return nil, fmt.Errorf("direct GCP public resource scanning requires exactly one --resource-type")
	}
	resourceType := c.ResourceType[0]
	if resolved, err := resolveAlias(resourceType); err == nil {
		resourceType = resolved
	}
	if !slices.Contains(publicResourceTypes, resourceType) {
		return nil, fmt.Errorf("resource type %q is not supported for direct GCP public resource scanning", resourceType)
	}

	inputs := make([]enumeration.ResourceIDInput, 0, len(c.ResourceID))
	for _, resourceID := range c.ResourceID {
		inputs = append(inputs, enumeration.ResourceIDInput{
			ProjectID:    c.ProjectID[0],
			ResourceType: resourceType,
			ResourceID:   resourceID,
		})
	}

	inputStream := pipeline.From(inputs...)
	listed := pipeline.New[output.GCPResource]()
	enumerator := enumeration.NewEnumerator(c.GCPCommonRecon)
	pipeline.Pipe(inputStream, enumerator.ListByResourceID, listed, &pipeline.PipeOpts{Concurrency: c.Concurrency})
	return listed, nil
}

// filterProjects extracts project IDs from the hierarchy stream, discarding
// non-project resources.
func filterProjects(res output.GCPResource, p *pipeline.P[string]) error {
	if res.ResourceType == "projects" {
		p.Send(res.ProjectID)
	}
	return nil
}
