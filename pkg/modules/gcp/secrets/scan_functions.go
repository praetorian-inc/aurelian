package secrets

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/janus-framework/pkg/links/noseyparker"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/applications"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/hierarchy"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("gcp", "secrets", GcpScanFunctions.Metadata().Properties()["id"].(string), *GcpScanFunctions)
}

var GcpScanFunctions = chain.NewModule(
	cfg.NewMetadata(
		"GCP Scan Functions Secrets",
		"List all Cloud Functions in a GCP project and scan them for secrets.",
	).WithProperties(map[string]any{
		"id":          "functions-secrets",
		"platform":    "gcp",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references":  []string{},
	}).WithChainInputParam(options.GcpProject().Name()),
).WithLinks(
	hierarchy.NewGcpProjectInfoLink,
	applications.NewGcpFunctionListLink,
	applications.NewGcpFunctionSecretsLink,
	chain.ConstructLinkWithConfigs(noseyparker.NewNoseyParkerScanner, cfg.WithArg("continue_piping", true)),
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
	outputters.NewNPFindingsConsoleOutputter,
).WithInputParam(
	options.GcpProject(),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "functions-secrets"),
)
