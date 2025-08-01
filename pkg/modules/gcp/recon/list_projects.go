package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/hierarchy"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("gcp", "recon", GcpListProjects.Metadata().Properties()["id"].(string), *GcpListProjects)
}

var GcpListProjects = chain.NewModule(
	cfg.NewMetadata(
		"GCP List Projects",
		"List all projects in a GCP organization.",
	).WithProperties(map[string]any{
		"id":          "projects-list",
		"platform":    "gcp",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references":  []string{},
	}).WithChainInputParam(options.GcpOrg().Name()),
).WithLinks(
	hierarchy.NewGcpOrgInfoLink,
	hierarchy.NewGcpOrgProjectListLink,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
).WithInputParam(
	options.GcpOrg(),
)
