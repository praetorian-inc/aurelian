package options

import (
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/types"
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
func DockerImage() cfg.Param {
	return cfg.NewParam[string]("image",
		"Docker image name to process. To download an image from a custom registry, prepend the\n"+
			"image name with the registry URL. Example: ghcr.io/oj/gobuster").
		WithShortcode("i")
}

func DockerUser() cfg.Param {
	return cfg.NewParam[string]("docker-user", "Docker registry username")
}

func DockerPassword() cfg.Param {
	return cfg.NewParam[string]("docker-password", "Docker registry password")
}

func DockerExtract() cfg.Param {
	return cfg.NewParam[bool]("extract", "Extract files from Docker image").
		WithDefault(true)
}

func NoseyParkerScan() cfg.Param {
	return cfg.NewParam[bool]("noseyparker-scan", "Enable NoseyParker scanning of extracted files").
		WithDefault(true)
}
