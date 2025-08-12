package docker

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/docker/client"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/janus-framework/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

type DockerSave struct {
	*chain.Base
	outDir string
}

func NewDockerSave(configs ...cfg.Config) chain.Link {
	dsl := &DockerSave{}
	dsl.Base = chain.NewBase(dsl, configs...)
	return dsl
}

func (dsl *DockerSave) Params() []cfg.Param {
	return []cfg.Param{
		options.OutputDir(),
	}
}

func (dsl *DockerSave) Initialize() error {
	dir, err := cfg.As[string](dsl.Arg("output"))
	if err != nil {
		return err
	}

	if dir == "" {
		dir = filepath.Join(os.TempDir(), ".janus-docker-images")
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	dsl.outDir = dir

	return nil
}

func (dsl *DockerSave) Process(imageContext types.DockerImage) error {
	isPublicImage := strings.Contains(imageContext.AuthConfig.ServerAddress, "public.ecr.aws")

	var dockerClient *client.Client
	var err error

	if !isPublicImage {
		dockerClient, err = NewAuthenticatedClient(dsl.Context(), imageContext, client.FromEnv)
	} else {
		dockerClient, err = NewUnauthenticatedClient(dsl.Context(), client.FromEnv)
	}

	if err != nil {
		return err
	}

	defer dockerClient.Close()

	imageID := imageContext.Image

	defer removeImage(dsl.Context(), dockerClient, imageID)

	outFile, err := dsl.createOutputFile(imageID)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	reader, err := dockerClient.ImageSave(dsl.Context(), []string{imageID})
	if err != nil {
		return fmt.Errorf("failed to save image: %w", err)
	}
	defer reader.Close()

	if _, err := io.Copy(outFile, reader); err != nil {
		return fmt.Errorf("failed to copy image to output file: %w", err)
	}

	imageContext.LocalPath = outFile.Name()

	return dsl.Send(&imageContext)
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