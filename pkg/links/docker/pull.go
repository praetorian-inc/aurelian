package docker

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/client"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/janus-framework/pkg/types"
)

type DockerPull struct {
	*chain.Base
	Client *client.Client
}

func NewDockerPull(configs ...cfg.Config) chain.Link {
	dp := &DockerPull{}
	dp.Base = chain.NewBase(dp, configs...)
	return dp
}

func (dp *DockerPull) Process(imageContext types.DockerImage) error {
	imageContext.Image = strings.TrimSpace(imageContext.Image)
	if imageContext.Image == "" {
		return nil
	}

	isPublicImage := strings.Contains(imageContext.AuthConfig.ServerAddress, "public.ecr.aws")

	var dockerClient *client.Client
	var err error
	var pullOpts image.PullOptions

	if !isPublicImage {
		dockerClient, err = dp.authenticate(imageContext, &pullOpts, client.FromEnv)
	} else {
		dockerClient, err = NewUnauthenticatedClient(dp.Context(), client.FromEnv)
	}

	if err != nil {
		return err
	}

	defer dockerClient.Close()

	reader, err := dockerClient.ImagePull(dp.Context(), imageContext.Image, pullOpts)
	if err != nil {
		slog.Error("Failed to pull container", "error", err)
		return nil
	}

	defer reader.Close()

	buf := &bytes.Buffer{}
	if _, err := io.Copy(buf, reader); err != nil {
		slog.Error("Failed to copy reader", "error", err)
		return nil
	}

	return dp.Send(&imageContext)
}

func (dp *DockerPull) authenticate(imageContext types.DockerImage, pullOpts *image.PullOptions, opts ...client.Opt) (*client.Client, error) {
	dockerClient, err := NewAuthenticatedClient(dp.Context(), imageContext, opts...)

	if err != nil {
		return nil, fmt.Errorf("failed to login to Docker registry: %w", err)
	}

	encodedAuthConfig, err := registry.EncodeAuthConfig(imageContext.AuthConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to encode auth config: %w", err)
	}

	pullOpts.RegistryAuth = encodedAuthConfig

	return dockerClient, nil
}