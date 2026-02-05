package options

import (
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

var DockerUserOpt = types.Option{
	Name:        "docker-user",
	Description: "Docker registry username",
	Required:    false,
	Type:        types.String,
	Value:       "",
}

var DockerPasswordOpt = types.Option{
	Name:        "docker-password",
	Description: "Docker registry password",
	Required:    false,
	Type:        types.String,
	Value:       "",
}

var DockerExtractOpt = types.Option{
	Name:        "docker-extract",
	Short:       "e",
	Description: "Extract files from Docker image",
	Required:    false,
	Type:        types.Bool,
	Value:       "",
}

// Janus framework parameters
func DockerImage() plugin.Parameter {
	return plugin.NewParam[string]("image",
		"Docker image name to process. To download an image from a custom registry, prepend the\n"+
			"image name with the registry URL. Example: ghcr.io/oj/gobuster",
		plugin.WithShortcode("i"),
	)
}

func DockerUser() plugin.Parameter {
	return plugin.NewParam[string]("docker-user", "Docker registry username")
}

func DockerPassword() plugin.Parameter {
	return plugin.NewParam[string]("docker-password", "Docker registry password")
}

func DockerExtract() plugin.Parameter {
	return plugin.NewParam[bool]("extract", "Extract files from Docker image",
		plugin.WithDefault(true),
	)
}

func NoseyParkerScan() plugin.Parameter {
	return plugin.NewParam[bool]("noseyparker-scan", "Enable NoseyParker scanning of extracted files",
		plugin.WithDefault(true),
	)
}
