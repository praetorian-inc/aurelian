package docker

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// DockerExtractToFS extracts Docker image files to the filesystem
type DockerExtractToFS struct {
	*plugin.BaseLink
	outDir string
}

func NewDockerExtractToFS(args map[string]any) *DockerExtractToFS {
	de := &DockerExtractToFS{
		BaseLink: plugin.NewBaseLink("docker-extract-fs", args),
	}

	// Initialize output directory
	dir := de.ArgString("output", "")
	de.outDir = dir

	// Create output directory
	if err := os.MkdirAll(dir, 0755); err != nil {
		de.Logger().Error("Failed to create extraction directory", "error", err)
	}

	return de
}

func (de *DockerExtractToFS) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "output",
			Description: "Output directory for extracted files",
			Required:    true,
			Type:        "string",
		},
		{
			Name:        "extract",
			Description: "Enable extraction to filesystem",
			Required:    false,
			Type:        "bool",
			Default:     true,
		},
	}
}

func (de *DockerExtractToFS) Process(ctx context.Context, input any) ([]any, error) {
	imageContext, ok := input.(types.DockerImage)
	if !ok {
		return nil, fmt.Errorf("expected types.DockerImage input, got %T", input)
	}

	extract := de.ArgBool("extract", true)
	if !extract {
		// Pass through without extraction
		return []any{&imageContext}, nil
	}

	if imageContext.LocalPath == "" {
		return nil, fmt.Errorf("no local path available for image %s", imageContext.Image)
	}

	// Create extraction directory for this image
	imageName := de.sanitizeImageName(imageContext.Image)
	extractDir := filepath.Join(de.outDir, imageName)

	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create image extraction directory: %w", err)
	}

	// Extract the Docker image tar file
	if err := de.extractTar(imageContext.LocalPath, extractDir); err != nil {
		return nil, fmt.Errorf("failed to extract Docker image: %w", err)
	}

	de.Logger().Info("Extracted Docker image to filesystem", "image", imageContext.Image, "path", extractDir)

	// Send the original imageContext to the next link for NoseyParker processing
	return []any{&imageContext}, nil
}

func (de *DockerExtractToFS) sanitizeImageName(imageName string) string {
	// Replace invalid characters for filesystem paths
	sanitized := strings.ReplaceAll(imageName, "/", "_")
	sanitized = strings.ReplaceAll(sanitized, ":", "_")
	sanitized = strings.ReplaceAll(sanitized, ".", "_")
	return sanitized
}

func (de *DockerExtractToFS) extractTar(tarPath, extractDir string) error {
	imageFile, err := os.Open(tarPath)
	if err != nil {
		return fmt.Errorf("failed to open tar file: %w", err)
	}
	defer imageFile.Close()

	// Extract Docker image tar using archive/tar
	tarReader := tar.NewReader(imageFile)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		// Create the full path for extraction
		targetPath := filepath.Join(extractDir, header.Name)

		// Ensure the target directory exists
		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", filepath.Dir(targetPath), err)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			// Create directory
			if err := os.MkdirAll(targetPath, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", targetPath, err)
			}
		case tar.TypeReg:
			// Extract regular file
			outFile, err := os.Create(targetPath)
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", targetPath, err)
			}

			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return fmt.Errorf("failed to extract file %s: %w", targetPath, err)
			}

			outFile.Close()

			// Set file permissions
			if err := os.Chmod(targetPath, os.FileMode(header.Mode)); err != nil {
				slog.Debug("failed to set file permissions", "file", targetPath, "error", err)
			}
		}
	}

	// Create extraction manifest
	manifestPath := filepath.Join(extractDir, "extraction-manifest.json")
	manifest := map[string]interface{}{
		"image":        filepath.Base(tarPath),
		"extracted_to": extractDir,
		"status":       "extracted",
	}

	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to create manifest: %w", err)
	}

	return os.WriteFile(manifestPath, manifestData, 0644)
}

// DockerExtractToNP converts Docker images to NoseyParker inputs
type DockerExtractToNP struct {
	*plugin.BaseLink
}

func NewDockerExtractToNP(args map[string]any) *DockerExtractToNP {
	return &DockerExtractToNP{
		BaseLink: plugin.NewBaseLink("docker-extract-np", args),
	}
}

func (de *DockerExtractToNP) Process(ctx context.Context, input any) ([]any, error) {
	imageContext, ok := input.(types.DockerImage)
	if !ok {
		return nil, fmt.Errorf("expected types.DockerImage input, got %T", input)
	}

	if imageContext.LocalPath == "" {
		return nil, fmt.Errorf("no local path available for image %s", imageContext.Image)
	}

	// Convert Docker image to NoseyParker inputs
	npInputs, err := imageContext.ToNPInputs()
	if err != nil {
		return nil, fmt.Errorf("failed to convert Docker image to NP inputs: %w", err)
	}

	de.Logger().Info("Converted Docker image to NoseyParker inputs",
		"image", imageContext.Image,
		"input_count", len(npInputs))

	// Send each NPInput individually
	outputs := make([]any, len(npInputs))
	for i, npInput := range npInputs {
		outputs[i] = &npInput
	}

	return outputs, nil
}

func (de *DockerExtractToNP) Parameters() []plugin.Parameter {
	return nil
}

// DockerImageLoader loads Docker images from various sources
type DockerImageLoader struct {
	*plugin.BaseLink
}

func NewDockerImageLoader(args map[string]any) *DockerImageLoader {
	return &DockerImageLoader{
		BaseLink: plugin.NewBaseLink("docker-image-loader", args),
	}
}

func (dl *DockerImageLoader) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "image",
			Description: "Docker image name",
			Required:    false,
			Type:        "string",
		},
		{
			Name:        "file",
			Description: "File containing list of images",
			Required:    false,
			Type:        "string",
		},
		{
			Name:        "docker-user",
			Description: "Docker registry username",
			Required:    false,
			Type:        "string",
		},
		{
			Name:        "docker-password",
			Description: "Docker registry password",
			Required:    false,
			Type:        "string",
		},
	}
}

func (dl *DockerImageLoader) Process(ctx context.Context, input any) ([]any, error) {
	// Handle single image input
	imageName := dl.ArgString("image", "")
	if imageName != "" {
		imageContext := dl.createImageContext(imageName)
		return []any{&imageContext}, nil
	}

	// Handle file input
	fileName := dl.ArgString("file", "")
	if fileName != "" {
		return dl.processFileInput(fileName)
	}

	// Process input string as image name if provided
	inputStr, ok := input.(string)
	if ok && inputStr != "" {
		imageContext := dl.createImageContext(inputStr)
		return []any{&imageContext}, nil
	}

	return nil, fmt.Errorf("no image name or file provided")
}

func (dl *DockerImageLoader) processFileInput(fileName string) ([]any, error) {
	fileContents, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", fileName, err)
	}

	lines := strings.Split(string(fileContents), "\n")
	outputs := []any{}
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		imageContext := dl.createImageContext(line)
		outputs = append(outputs, &imageContext)
	}

	return outputs, nil
}

func (dl *DockerImageLoader) createImageContext(imageName string) types.DockerImage {
	imageContext := types.DockerImage{
		Image: imageName,
	}

	// Add authentication if provided
	username := dl.ArgString("docker-user", "")
	password := dl.ArgString("docker-password", "")

	if username != "" && password != "" {
		imageContext.AuthConfig.Username = username
		imageContext.AuthConfig.Password = password
	}

	// Extract server address from image name
	parts := strings.SplitN(imageName, "/", 2)
	if len(parts) == 2 && strings.Contains(parts[0], ".") {
		imageContext.AuthConfig.ServerAddress = "https://" + parts[0]
		imageContext.Image = parts[1]
	}

	return imageContext
}
