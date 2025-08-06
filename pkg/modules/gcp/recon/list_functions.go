package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/applications"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/hierarchy"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("gcp", "recon", GcpListFunctions.Metadata().Properties()["id"].(string), *GcpListFunctions)
}

var GcpListFunctions = chain.NewModule(
	cfg.NewMetadata(
		"GCP List Functions",
		"List all Cloud Functions in a GCP project.",
	).WithProperties(map[string]any{
		"id":          "functions-list",
		"platform":    "gcp",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references":  []string{},
	}).WithChainInputParam(options.GcpProject().Name()),
).WithLinks(
	hierarchy.NewGcpProjectInfoLink,
	applications.NewGcpFunctionListLink,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
).WithInputParam(
	options.GcpProject(),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "functions-list"),
)
