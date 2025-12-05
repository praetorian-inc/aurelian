package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	janusDocker "github.com/praetorian-inc/janus-framework/pkg/links/docker"
	"github.com/praetorian-inc/janus-framework/pkg/links/noseyparker"
	"github.com/praetorian-inc/nebula/internal/registry"
	"github.com/praetorian-inc/nebula/pkg/links/docker"
	"github.com/praetorian-inc/nebula/pkg/links/options"
	"github.com/praetorian-inc/nebula/pkg/outputters"
)

var DockerDump = chain.NewModule(
	cfg.NewMetadata(
		"Docker Container Dumper",
		"Extract the file contents of a Docker container and optionally scan for secrets using NoseyParker.",
	).WithProperties(map[string]any{
		"id":          "docker-dump",
		"platform":    "universal",
		"opsec_level": "none",
		"authors":     []string{"Praetorian"},
	}),
).WithLinks(
	docker.NewDockerImageLoader,
	janusDocker.NewDockerGetLayers,
	janusDocker.NewDockerDownloadLayer,
	janusDocker.NewDockerLayerToNP,
	chain.ConstructLinkWithConfigs(noseyparker.NewNoseyParkerScanner,
		cfg.WithArg("continue_piping", true)),
).WithInputParam(
	options.DockerImage(),
).WithConfigs(
	cfg.WithArg("docker-user", ""),
	cfg.WithArg("docker-password", ""),
	cfg.WithArg("extract", "true"),
	cfg.WithArg("noseyparker-scan", "true"),
	cfg.WithArg("module-name", "docker-dump"),
	cfg.WithArg("max-file-size", 10),
).WithParams(
	cfg.NewParam[string]("module-name", "name of the module for dynamic file naming"),
	cfg.NewParam[int]("max-file-size", "maximum file size to scan (in MB)").WithDefault(10),
).WithOutputters(
	outputters.NewNPFindingsConsoleOutputter,
).WithAutoRun()

func init() {
	registry.Register("saas", "recon", "docker-dump", *DockerDump)
}
