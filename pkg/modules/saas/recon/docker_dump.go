package recon

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/docker"
	"github.com/praetorian-inc/janus-framework/pkg/links/noseyparker"
	"github.com/praetorian-inc/nebula/internal/registry"
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
	// Load Docker images from file or single image input
	docker.NewDockerImageLoader,
	// Pull the Docker images
	docker.NewDockerPull,
	// Save images to local tar files
	docker.NewDockerSave,
	// Extract to filesystem
	docker.NewDockerExtractToFS,
	// Convert to NoseyParker inputs and scan
	docker.NewDockerExtractToNP,
	chain.ConstructLinkWithConfigs(noseyparker.NewNoseyParkerScanner, 
		cfg.WithArg("continue_piping", true)),
).WithInputParam(
	options.DockerImage(),
).WithConfigs(
	cfg.WithArg("file", ""),
	cfg.WithArg("docker-user", ""),
	cfg.WithArg("docker-password", ""),
	cfg.WithArg("extract", "true"),
	cfg.WithArg("noseyparker-scan", "true"),
).WithOutputters(
	outputters.NewRuntimeJSONOutputter,
	outputters.NewNPFindingsConsoleOutputter,
).WithAutoRun()

func init() {
	registry.Register("saas", "recon", "docker-dump", *DockerDump)
}