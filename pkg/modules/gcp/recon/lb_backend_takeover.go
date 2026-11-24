package recon

import (
	"github.com/praetorian-inc/aurelian/pkg/gcp/dnstakeover"
	"github.com/praetorian-inc/aurelian/pkg/gcp/hierarchy"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&GCPLbBackendTakeoverModule{})
}

type GCPLbBackendTakeoverConfig struct {
	plugin.GCPCommonRecon
}

type GCPLbBackendTakeoverModule struct {
	GCPLbBackendTakeoverConfig
}

func (m *GCPLbBackendTakeoverModule) ID() string                { return "lb-backend-takeover" }
func (m *GCPLbBackendTakeoverModule) Name() string              { return "GCP LB Backend Bucket Takeover" }
func (m *GCPLbBackendTakeoverModule) Platform() plugin.Platform { return plugin.PlatformGCP }
func (m *GCPLbBackendTakeoverModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *GCPLbBackendTakeoverModule) OpsecLevel() string        { return "moderate" }
func (m *GCPLbBackendTakeoverModule) Authors() []string         { return []string{"Praetorian"} }
func (m *GCPLbBackendTakeoverModule) Parameters() any           { return &m.GCPLbBackendTakeoverConfig }

func (m *GCPLbBackendTakeoverModule) Description() string {
	return "Detect GCP HTTPS Load Balancer backend buckets pointing to non-existent GCS buckets. " +
		"A dangling backend bucket allows an attacker to create the missing GCS bucket and serve " +
		"malicious content through the load balancer."
}

func (m *GCPLbBackendTakeoverModule) References() []string {
	return []string{
		"https://cloud.google.com/load-balancing/docs/https",
		"https://cloud.google.com/load-balancing/docs/backend-bucket",
	}
}

func (m *GCPLbBackendTakeoverModule) SupportedResourceTypes() []string {
	return supportedInputTypes
}

func (m *GCPLbBackendTakeoverModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.GCPLbBackendTakeoverConfig

	checker, err := dnstakeover.NewBackendBucketChecker(c.ClientOptions)
	if err != nil {
		return err
	}

	cfg.Info("scanning for dangling backend buckets")

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

	pipeline.Pipe(projects, checker.CheckProject, out, &pipeline.PipeOpts{
		Progress:    cfg.Log.ProgressFunc("checking backend buckets"),
		Concurrency: c.Concurrency,
	})

	if err := out.Wait(); err != nil {
		return err
	}
	cfg.Success("backend bucket takeover scan complete")
	return nil
}
