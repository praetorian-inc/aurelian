package docker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/client"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

type DockerPull struct {
	*plugin.BaseLink
	Client *client.Client
}

func NewDockerPull(args map[string]any) *DockerPull {
	return &DockerPull{
		BaseLink: plugin.NewBaseLink("docker-pull", args),
	}
}

func (dp *DockerPull) Process(ctx context.Context, input any) ([]any, error) {
	imageContext, ok := input.(types.DockerImage)
	if !ok {
		return nil, fmt.Errorf("expected types.DockerImage input, got %T", input)
	}

	imageContext.Image = strings.TrimSpace(imageContext.Image)
	if imageContext.Image == "" {
		return []any{}, nil
	}

	isPublicImage := strings.Contains(imageContext.AuthConfig.ServerAddress, "public.ecr.aws")

	var dockerClient *client.Client
	var err error
	var pullOpts image.PullOptions

	if !isPublicImage {
		dockerClient, err = dp.authenticate(ctx, imageContext, &pullOpts, client.FromEnv)
	} else {
		dockerClient, err = NewUnauthenticatedClient(ctx, client.FromEnv)
	}

	if err != nil {
		return nil, err
	}

	defer dockerClient.Close()

	reader, err := dockerClient.ImagePull(ctx, imageContext.Image, pullOpts)
	if err != nil {
		slog.Error("Failed to pull container", "error", err)
		return []any{}, nil
	}

	defer reader.Close()

	buf := &bytes.Buffer{}
	if _, err := io.Copy(buf, reader); err != nil {
		slog.Error("Failed to copy reader", "error", err)
		return []any{}, nil
	}

	return []any{&imageContext}, nil
}

func (dp *DockerPull) authenticate(ctx context.Context, imageContext types.DockerImage, pullOpts *image.PullOptions, opts ...client.Opt) (*client.Client, error) {
	dockerClient, err := NewAuthenticatedClient(ctx, imageContext, opts...)

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

func (dp *DockerPull) Parameters() []plugin.Parameter {
	return nil
}
