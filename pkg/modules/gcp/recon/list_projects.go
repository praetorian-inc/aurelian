package recon

import (
	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/hierarchy"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	GcpListProjects.New().Initialize()
	registry.Register("gcp", "recon", GcpListProjects.Metadata().Properties()["id"].(string), *GcpListProjects)
}

var GcpListProjects = chain.NewModule(
	cfg.NewMetadata(
		"GCP List Organization Projects",
		"List all projects in a GCP organization.",
	).WithProperties(map[string]any{
		"id":          "list-org-projects",
		"platform":    "gcp",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references":  []string{},
	}).WithChainInputParam(options.GcpOrgResource().Name()),
).WithLinks(
	hierarchy.NewGcpOrgProjectListLink,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
)
