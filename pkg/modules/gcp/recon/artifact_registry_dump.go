package recon

import (
	"github.com/praetorian-inc/aurelian/pkg/gcp/enumeration"
	"github.com/praetorian-inc/aurelian/pkg/gcp/hierarchy"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&GCPArtifactRegistryDumpModule{})
}

type GCPARDumpConfig struct {
	plugin.GCPCommonRecon
}

type GCPArtifactRegistryDumpModule struct {
	GCPARDumpConfig
}

func (m *GCPArtifactRegistryDumpModule) ID() string                { return "artifact-registry-dump" }
func (m *GCPArtifactRegistryDumpModule) Name() string              { return "GCP Artifact Registry Dump" }
func (m *GCPArtifactRegistryDumpModule) Platform() plugin.Platform { return plugin.PlatformGCP }
func (m *GCPArtifactRegistryDumpModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *GCPArtifactRegistryDumpModule) OpsecLevel() string        { return "moderate" }
func (m *GCPArtifactRegistryDumpModule) Authors() []string         { return []string{"Praetorian"} }
func (m *GCPArtifactRegistryDumpModule) Description() string {
	return "Enumerate Artifact Registry repositories and Docker images across GCP projects."
}
func (m *GCPArtifactRegistryDumpModule) References() []string {
	return []string{"https://cloud.google.com/artifact-registry/docs/reference/rest"}
}
func (m *GCPArtifactRegistryDumpModule) SupportedResourceTypes() []string { return nil }
func (m *GCPArtifactRegistryDumpModule) Parameters() any                  { return &m.GCPARDumpConfig }

func (m *GCPArtifactRegistryDumpModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.GCPARDumpConfig

	resolver := hierarchy.NewResolver(c.GCPCommonRecon)
	input := hierarchy.HierarchyResolverInput{
		OrgIDs: c.OrgID, FolderIDs: c.FolderID, ProjectIDs: c.ProjectID,
	}
	hierarchyStream := pipeline.From(input)
	resolved := pipeline.New[output.GCPResource]()
	pipeline.Pipe(hierarchyStream, resolver.Resolve, resolved)

	projects := pipeline.New[string]()
	pipeline.Pipe(resolved, func(res output.GCPResource, p *pipeline.P[string]) error {
		if res.ResourceType == "projects" {
			p.Send(res.ProjectID)
		}
		return nil
	}, projects)

	lister := enumeration.NewArtifactRegistryLister(c.ClientOptions)
	listed := pipeline.New[output.GCPResource]()
	pipeline.Pipe(projects, func(projectID string, p *pipeline.P[output.GCPResource]) error {
		cfg.Info("enumerating artifact registry for project %s", projectID)
		return lister.List(projectID, p)
	}, listed)

	pipeline.Pipe(listed, func(res output.GCPResource, p *pipeline.P[model.AurelianModel]) error {
		p.Send(res)
		return nil
	}, out)

	return out.Wait()
}
