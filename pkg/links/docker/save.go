package docker

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/docker/client"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

type DockerSave struct {
	*plugin.BaseLink
	outDir string
}

func NewDockerSave(args map[string]any) *DockerSave {
	ds := &DockerSave{
		BaseLink: plugin.NewBaseLink("docker-save", args),
	}

	// Initialize output directory
	dir := ds.ArgString("output", "")
	if dir == "" {
		dir = filepath.Join(os.TempDir(), ".janus-docker-images")
	}
	ds.outDir = dir

	// Create output directory
	if err := os.MkdirAll(dir, 0755); err != nil {
		ds.Logger().Error("Failed to create output directory", "error", err)
	}

	return ds
}

func (dsl *DockerSave) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "output",
			Description: "Output directory for saved Docker images",
			Required:    false,
			Type:        "string",
		},
	}
}

func (dsl *DockerSave) Process(ctx context.Context, input any) ([]any, error) {
	imageContext, ok := input.(types.DockerImage)
	if !ok {
		return nil, fmt.Errorf("expected types.DockerImage input, got %T", input)
	}

	isPublicImage := strings.Contains(imageContext.AuthConfig.ServerAddress, "public.ecr.aws")

	var dockerClient *client.Client
	var err error

	if !isPublicImage {
		dockerClient, err = NewAuthenticatedClient(ctx, imageContext, client.FromEnv)
	} else {
		dockerClient, err = NewUnauthenticatedClient(ctx, client.FromEnv)
	}

	if err != nil {
		return nil, err
	}

	defer dockerClient.Close()

	imageID := imageContext.Image

	defer removeImage(ctx, dockerClient, imageID)

	outFile, err := dsl.createOutputFile(imageID)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	reader, err := dockerClient.ImageSave(ctx, []string{imageID})
	if err != nil {
		return nil, fmt.Errorf("failed to save image: %w", err)
	}
	defer reader.Close()

	if _, err := io.Copy(outFile, reader); err != nil {
		return nil, fmt.Errorf("failed to copy image to output file: %w", err)
	}

	imageContext.LocalPath = outFile.Name()

	return []any{&imageContext}, nil
}

func (dsl *DockerSave) createOutputFile(imageID string) (*os.File, error) {
	parts := strings.Split(imageID, "/")
	imageName := strings.Replace(parts[len(parts)-1], ":", "-", -1)

	outputPath := filepath.Join(dsl.outDir, imageName+".tar")
	outFile, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %w", err)
	}

	return outFile, nil
}
