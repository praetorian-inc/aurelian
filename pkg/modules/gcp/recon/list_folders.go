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
	registry.Register("gcp", "recon", GcpListFolders.Metadata().Properties()["id"].(string), *GcpListFolders)
}

var GcpListFolders = chain.NewModule(
	cfg.NewMetadata(
		"GCP List Folders",
		"List all folders in a GCP organization.",
	).WithProperties(map[string]any{
		"id":          "folders-list",
		"platform":    "gcp",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references":  []string{},
	}).WithChainInputParam(options.GcpOrg().Name()),
).WithLinks(
	hierarchy.NewGcpOrgInfoLink,
	hierarchy.NewGcpOrgFolderListLink,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
).WithInputParam(
	options.GcpOrg(),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "folders-list"),
)
