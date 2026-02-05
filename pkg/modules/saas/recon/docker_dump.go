package recon

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&DockerDump{})
}

// DockerDump extracts the file contents of a Docker container and optionally scans for secrets
type DockerDump struct{}

// Metadata methods
func (m *DockerDump) ID() string                        { return "docker-dump" }
func (m *DockerDump) Name() string                      { return "Docker Container Dumper" }
func (m *DockerDump) Platform() plugin.Platform         { return plugin.PlatformSaaS }
func (m *DockerDump) Category() plugin.Category         { return plugin.CategoryRecon }
func (m *DockerDump) OpsecLevel() string                { return "none" }
func (m *DockerDump) Authors() []string                 { return []string{"Praetorian"} }
func (m *DockerDump) References() []string              { return nil }

func (m *DockerDump) Description() string {
	return "Extract the file contents of a Docker container and optionally scan for secrets using NoseyParker."
}

// Parameters defines the module's configurable parameters
func (m *DockerDump) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "docker-image",
			Description: "Docker image to dump (e.g., nginx:latest)",
			Type:        "string",
			Required:    true,
		},
		{
			Name:        "docker-user",
			Description: "Docker registry username (if authentication required)",
			Type:        "string",
			Required:    false,
			Default:     "",
		},
		{
			Name:        "docker-password",
			Description: "Docker registry password (if authentication required)",
			Type:        "string",
			Required:    false,
			Default:     "",
		},
		{
			Name:        "extract",
			Description: "Extract container layers",
			Type:        "bool",
			Required:    false,
			Default:     true,
		},
		{
			Name:        "noseyparker-scan",
			Description: "Scan extracted files for secrets using NoseyParker",
			Type:        "bool",
			Required:    false,
			Default:     true,
		},
		{
			Name:        "max-file-size",
			Description: "Maximum file size to scan (in MB)",
			Type:        "int",
			Required:    false,
			Default:     10,
		},
		{
			Name:        "continue-piping",
			Description: "Continue processing pipeline on errors",
			Type:        "bool",
			Required:    false,
			Default:     true,
		},
	}
}

// Run executes the Docker dump module
func (m *DockerDump) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Extract required parameters
	dockerImage, ok := cfg.Args["docker-image"].(string)
	if !ok || dockerImage == "" {
		return nil, fmt.Errorf("docker-image parameter is required")
	}

	// Optional authentication
	dockerUser, _ := cfg.Args["docker-user"].(string)
	dockerPassword, _ := cfg.Args["docker-password"].(string)

	// Optional flags with defaults
	extract := getBool(cfg.Args, "extract", true)
	noseyparkerScan := getBool(cfg.Args, "noseyparker-scan", true)
	maxFileSize := getInt(cfg.Args, "max-file-size", 10)
	continuePiping := getBool(cfg.Args, "continue-piping", true)

	// Implementation note: This is a placeholder for the actual implementation
	// The original Janus-based implementation chained together:
	// 1. docker.NewDockerImageLoader - Load Docker image with auth
	// 2. janusDocker.NewDockerGetLayers - Get image layers
	// 3. janusDocker.NewDockerDownloadLayer - Download each layer
	// 4. janusDocker.NewDockerLayerToNP - Convert layers for scanning
	// 5. noseyparker.NewNoseyParkerScanner - Scan for secrets
	//
	// TODO: Port these link implementations to native plugin functions

	ctx := cfg.Context
	if ctx == nil {
		ctx = context.Background()
	}

	// Suppress unused variable warnings until implementation is complete
	_ = dockerUser
	_ = dockerPassword
	_ = ctx

	// Temporary implementation that returns an error indicating porting is needed
	return nil, fmt.Errorf("module ported to native plugin architecture but link implementations need migration: image=%s, extract=%v, scan=%v, max-size=%d, continue-piping=%v",
		dockerImage, extract, noseyparkerScan, maxFileSize, continuePiping)
}

// Helper functions for type-safe parameter access
func getBool(args map[string]any, key string, defaultVal bool) bool {
	if val, ok := args[key].(bool); ok {
		return val
	}
	return defaultVal
}

func getInt(args map[string]any, key string, defaultVal int) int {
	if val, ok := args[key].(int); ok {
		return val
	}
	return defaultVal
}

// Helper functions for future implementation

// loadDockerImage loads a Docker image from registry
func loadDockerImage(ctx context.Context, image, user, password string) (any, error) {
	// TODO: Implement Docker image loading with authentication
	// Original: docker.NewDockerImageLoader
	return nil, fmt.Errorf("not implemented")
}

// extractLayers extracts container layers from image data
func extractLayers(ctx context.Context, imageData any) ([]any, error) {
	// TODO: Implement layer extraction logic
	// Original: janusDocker.NewDockerGetLayers + NewDockerDownloadLayer
	return nil, fmt.Errorf("not implemented")
}

// convertLayersForScanning converts layers to format suitable for NoseyParker
func convertLayersForScanning(ctx context.Context, layers []any) ([]any, error) {
	// TODO: Implement layer conversion
	// Original: janusDocker.NewDockerLayerToNP
	return nil, fmt.Errorf("not implemented")
}

// scanForSecrets scans extracted layers for secrets using NoseyParker
func scanForSecrets(ctx context.Context, data []any, maxFileSizeMB int) ([]plugin.Result, error) {
	// TODO: Implement NoseyParker scanning logic
	// Original: noseyparker.NewNoseyParkerScanner with continue_piping config
	return nil, fmt.Errorf("not implemented")
}
