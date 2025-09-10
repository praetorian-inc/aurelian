package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/containers"
	"github.com/praetorian-inc/nebula/pkg/links/gcp/hierarchy"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

func init() {
	registry.Register("gcp", "recon", GcpListArtifactory.Metadata().Properties()["id"].(string), *GcpListArtifactory)
}

var GcpListArtifactory = chain.NewModule(
	cfg.NewMetadata(
		"GCP List Artifactory",
		"List all Artifact Registry repositories and container images in a GCP project.",
	).WithProperties(map[string]any{
		"id":          "artifactory-list",
		"platform":    "gcp",
		"opsec_level": "moderate",
		"authors":     []string{"Praetorian"},
		"references":  []string{},
	}).WithChainInputParam(options.GcpProject().Name()),
).WithLinks(
	hierarchy.NewGcpProjectInfoLink,
	containers.NewGcpRepositoryListLink,
	containers.NewGcpContainerImageListLink,
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
).WithInputParam(
	options.GcpProject(),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
).WithConfigs(
	cfg.WithArg("module-name", "artifactory-list"),
)
