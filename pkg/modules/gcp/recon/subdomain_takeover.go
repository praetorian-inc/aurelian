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
	plugin.Register(&GCPSubdomainTakeoverModule{})
}

type GCPSubdomainTakeoverConfig struct {
	plugin.GCPCommonRecon
}

type GCPSubdomainTakeoverModule struct {
	GCPSubdomainTakeoverConfig
}

func (m *GCPSubdomainTakeoverModule) ID() string                { return "subdomain-takeover" }
func (m *GCPSubdomainTakeoverModule) Name() string              { return "GCP Subdomain Takeover" }
func (m *GCPSubdomainTakeoverModule) Platform() plugin.Platform { return plugin.PlatformGCP }
func (m *GCPSubdomainTakeoverModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *GCPSubdomainTakeoverModule) OpsecLevel() string        { return "moderate" }
func (m *GCPSubdomainTakeoverModule) Authors() []string         { return []string{"Praetorian"} }
func (m *GCPSubdomainTakeoverModule) Parameters() any           { return &m.GCPSubdomainTakeoverConfig }

func (m *GCPSubdomainTakeoverModule) Description() string {
	return "Scan for dangling DNS records in Cloud DNS that could enable subdomain takeover. " +
		"Checks CNAME records for non-existent Cloud Storage buckets, Cloud Run services, " +
		"and App Engine apps; A/AAAA records for orphaned IPs; and NS delegations to " +
		"unclaimed Cloud DNS zones."
}

func (m *GCPSubdomainTakeoverModule) References() []string {
	return []string{
		"https://cloud.google.com/dns/docs/overview",
		"https://developer.mozilla.org/en-US/docs/Web/Security/Subdomain_takeovers",
	}
}

func (m *GCPSubdomainTakeoverModule) SupportedResourceTypes() []string {
	return supportedInputTypes
}

func (m *GCPSubdomainTakeoverModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.GCPSubdomainTakeoverConfig

	checker, err := dnstakeover.NewChecker(c.ClientOptions)
	if err != nil {
		return err
	}

	cfg.Info("scanning Cloud DNS for dangling records")

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

	enumerator := dnstakeover.NewDNSEnumerator(c.ClientOptions)
	records := pipeline.New[dnstakeover.DNSRecord]()
	pipeline.Pipe(projects, enumerator.EnumerateProject, records, &pipeline.PipeOpts{
		Progress: cfg.Log.ProgressFunc("enumerating dns records"),
	})

	pipeline.Pipe(records, checker.Check, out, &pipeline.PipeOpts{
		Progress:    cfg.Log.ProgressFunc("checking for takeover"),
		Concurrency: c.Concurrency,
	})

	if err := out.Wait(); err != nil {
		return err
	}
	cfg.Success("subdomain takeover scan complete")
	return nil
}
