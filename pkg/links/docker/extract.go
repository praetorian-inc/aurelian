package docker

import (
	"archive/tar"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/janus-framework/pkg/types"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

// DockerExtractToFS extracts Docker image files to the filesystem
type DockerExtractToFS struct {
	*chain.Base
	outDir string
}

func NewDockerExtractToFS(configs ...cfg.Config) chain.Link {
	de := &DockerExtractToFS{}
	de.Base = chain.NewBase(de, configs...)
	return de
}

func (de *DockerExtractToFS) Params() []cfg.Param {
	return []cfg.Param{
		options.OutputDir(),
		cfg.NewParam[bool]("extract", "enable extraction to filesystem").WithDefault(true),
	}
}

func (de *DockerExtractToFS) Initialize() error {
	dir, err := cfg.As[string](de.Arg("output"))
	if err != nil {
		return err
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create extraction directory: %w", err)
	}

	de.outDir = dir
	return nil
}

func (de *DockerExtractToFS) Process(imageContext types.DockerImage) error {
	extract, err := cfg.As[bool](de.Arg("extract"))
	if err != nil || !extract {
		// Pass through without extraction
		return de.Send(&imageContext)
	}

	if imageContext.LocalPath == "" {
		return fmt.Errorf("no local path available for image %s", imageContext.Image)
	}

	// Create extraction directory for this image
	imageName := de.sanitizeImageName(imageContext.Image)
	extractDir := filepath.Join(de.outDir, imageName)
	
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		return fmt.Errorf("failed to create image extraction directory: %w", err)
	}

	// Extract the Docker image tar file
	if err := de.extractTar(imageContext.LocalPath, extractDir); err != nil {
		return fmt.Errorf("failed to extract Docker image: %w", err)
	}

	de.Logger.Info("Extracted Docker image to filesystem", "image", imageContext.Image, "path", extractDir)
	
	// Send the original imageContext to the next link for NoseyParker processing
	return de.Send(&imageContext)
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
				de.Logger.Debug("failed to set file permissions", "file", targetPath, "error", err)
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
	*chain.Base
}

func NewDockerExtractToNP(configs ...cfg.Config) chain.Link {
	de := &DockerExtractToNP{}
	de.Base = chain.NewBase(de, configs...)
	return de
}

func (de *DockerExtractToNP) Process(imageContext types.DockerImage) error {
	if imageContext.LocalPath == "" {
		return fmt.Errorf("no local path available for image %s", imageContext.Image)
	}

	// Convert Docker image to NoseyParker inputs
	npInputs, err := imageContext.ToNPInputs()
	if err != nil {
		return fmt.Errorf("failed to convert Docker image to NP inputs: %w", err)
	}

	de.Logger.Info("Converted Docker image to NoseyParker inputs", 
		"image", imageContext.Image, 
		"input_count", len(npInputs))

	// Send each NPInput individually
	for _, npInput := range npInputs {
		if err := de.Send(&npInput); err != nil {
			return err
		}
	}

	return nil
}

// DockerImageLoader loads Docker images from various sources
type DockerImageLoader struct {
	*chain.Base
}

func NewDockerImageLoader(configs ...cfg.Config) chain.Link {
	dl := &DockerImageLoader{}
	dl.Base = chain.NewBase(dl, configs...)
	return dl
}

func (dl *DockerImageLoader) Params() []cfg.Param {
	return []cfg.Param{
		options.DockerImage(),
		options.File(),
		options.DockerUser(),
		options.DockerPassword(),
	}
}

func (dl *DockerImageLoader) Process(input string) error {
	// Handle single image input
	imageName, err := cfg.As[string](dl.Arg("image"))
	if err == nil && imageName != "" {
		imageContext := dl.createImageContext(imageName)
		return dl.Send(&imageContext)
	}

	// Handle file input
	fileName, err := cfg.As[string](dl.Arg("file"))
	if err == nil && fileName != "" {
		return dl.processFileInput(fileName)
	}

	// Process input string as image name if provided
	if input != "" {
		imageContext := dl.createImageContext(input)
		return dl.Send(&imageContext)
	}

	return fmt.Errorf("no image name or file provided")
}

func (dl *DockerImageLoader) processFileInput(fileName string) error {
	fileContents, err := os.ReadFile(fileName)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", fileName, err)
	}

	lines := strings.Split(string(fileContents), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		imageContext := dl.createImageContext(line)
		if err := dl.Send(&imageContext); err != nil {
			return err
		}
	}

	return nil
}

func (dl *DockerImageLoader) createImageContext(imageName string) types.DockerImage {
	imageContext := types.DockerImage{
		Image: imageName,
	}

	// Add authentication if provided
	username, _ := cfg.As[string](dl.Arg("docker-user"))
	password, _ := cfg.As[string](dl.Arg("docker-password"))

	if username != "" && password != "" {
		imageContext.AuthConfig.Username = username
		imageContext.AuthConfig.Password = password
	}

	// Extract server address from image name
	parts := strings.SplitN(imageName, "/", 2)
	if strings.Contains(parts[0], ".") {
		imageContext.AuthConfig.ServerAddress = "https://" + parts[0]
		imageContext.Image = parts[1]
	}

	return imageContext
}
