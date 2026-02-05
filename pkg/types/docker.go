package types

import (
	"fmt"

	"github.com/docker/docker/api/types/registry"
)

// DockerImage represents a Docker image with authentication context
type DockerImage struct {
	Image      string
	LocalPath  string
	ExtractDir string
	AuthConfig registry.AuthConfig
}

// ToNPInputs converts a Docker image to NoseyParker inputs
func (d *DockerImage) ToNPInputs() ([]NpInput, error) {
	if d.LocalPath == "" {
		return nil, fmt.Errorf("no local path available for Docker image")
	}

	// Create NoseyParker input from the Docker image tar file
	npInput := NpInput{
		Provenance: NpProvenance{
			Platform:     "docker",
			ResourceType: "container-image",
			ResourceID:   d.Image,
			FilePath:     d.LocalPath,
		},
	}

	return []NpInput{npInput}, nil
}
