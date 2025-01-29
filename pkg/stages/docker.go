package stages

import (
	"archive/tar"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/client"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

type ImageContext struct {
	AuthConfig registry.AuthConfig
	Image      string
}

func DockerOpts2ImageContext(opts []*types.Option) ImageContext {
	return ImageContext{
		AuthConfig: registry.AuthConfig{
			Username: options.GetOptionByName(options.DockerUserOpt.Name, opts).Value,
			Password: options.GetOptionByName(options.DockerPasswordOpt.Name, opts).Value,
		},
		Image: options.GetOptionByName(options.ImageOpt.Name, opts).Value,
	}
}

func DockerPullStage(ctx context.Context, opts []*types.Option, in <-chan ImageContext) <-chan string {
	logger := logs.NewStageLogger(ctx, opts, "DockerPullStage")
	out := make(chan string)

	go func() {
		defer close(out)

		// Initialize Docker client
		cli, err := client.NewClientWithOpts(client.FromEnv)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to create Docker client: %v", err))
			return
		}
		defer cli.Close()

		for c := range in {
			c.Image = strings.TrimSpace(c.Image)
			if c.Image == "" {
				continue
			}

			logger.Info(fmt.Sprintf("Pulling container: %s", c.Image))

			pullOpts := image.PullOptions{}
			if !isPublicImage(c.AuthConfig.ServerAddress) {
				logger.Debug(fmt.Sprintf("AuthConfig: %+v", c.AuthConfig))
				if _, err := cli.RegistryLogin(ctx, c.AuthConfig); err != nil {
					logger.Error(fmt.Sprintf("Failed to login to Docker registry: %v", err))
					continue
				}
				encodedAuthConfig, err := registry.EncodeAuthConfig(c.AuthConfig)
				if err != nil {
					logger.Error(fmt.Sprintf("Failed to encode auth config: %v", err))
					continue
				}
				pullOpts.RegistryAuth = encodedAuthConfig
			}

			reader, err := cli.ImagePull(ctx, c.Image, pullOpts)
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to pull container %s: %v", c.Image, err))
				continue
			}
			io.Copy(io.Discard, reader)
			reader.Close()

			out <- c.Image
		}
	}()

	return out
}

// DockerSaveStage saves Docker images to the filesystem
func DockerSaveStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan string {
	logger := logs.NewStageLogger(ctx, opts, "DockerSaveStage")
	out := make(chan string)

	go func() {
		defer close(out)

		cli, err := client.NewClientWithOpts(client.FromEnv)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to create Docker client: %v", err))
			return
		}
		defer cli.Close()

		for image := range in {
			defer removeImage(ctx, cli, image)

			// Get image name for directory
			name := getImageName(image)
			outputDir := filepath.Join(options.GetOptionByName(options.OutputOpt.Name, opts).Value, name)

			if err := os.MkdirAll(outputDir, 0755); err != nil {
				logger.Error(fmt.Sprintf("Failed to create directory: %v", err))
				continue
			}

			// Save image using Docker image save
			reader, err := cli.ImageSave(ctx, []string{image})
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to save image: %v", err))
				continue
			}
			defer reader.Close()

			// Save to file
			outputPath := filepath.Join(outputDir, name+".tar")
			outFile, err := os.Create(outputPath)
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to create output file: %v", err))
				continue
			}

			_, err = io.Copy(outFile, reader)
			outFile.Close()
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to write image: %v", err))
				continue
			}

			out <- outputPath
		}
	}()

	return out
}

func DockerExtractDomain(rawURL string) (string, error) {
	// If URL doesn't start with a protocol, prepend "https://"
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse URL: %v", err)
	}
	return parsedURL.Host, nil
}

// DockerExtractContainer extracts the container reference from a Docker container URL
func DockerExtractContainer(url string) (string, error) {
	// Split by "/" to separate domain and path
	parts := strings.Split(url, "/")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid container URL format")
	}

	// Get the last part which contains the full container reference
	container := parts[len(parts)-1]

	return container, nil
}

// DockerExtractRegion extracts the region from a Docker container URL
func DockerExtractRegion(url string) (string, error) {

	if strings.Contains(url, "public.ecr.aws") {
		return "us-east-1", nil
	}

	// Pattern matches: after "ecr." and before ".amazonaws.com"
	pattern := regexp.MustCompile(`ecr\.([-a-z0-9]+)\.amazonaws\.com`)

	matches := pattern.FindStringSubmatch(url)
	if len(matches) < 2 {
		return "", fmt.Errorf("no region found in URL: %s", url)
	}

	return matches[1], nil
}

func getImageName(image string) string {
	parts := strings.Split(image, "/")
	return strings.Replace(parts[len(parts)-1], ":", "_", -1)
}

func isPublicImage(url string) bool {
	return strings.Contains(url, "public.ecr.aws")
}

// func cleanupContainer(ctx context.Context, cli *client.Client, containerID string) {
// 	if err := cli.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: true}); err != nil {
// 		slog.Error("failed to remove container", slog.String("containerId", containerID), slog.String("error", err.Error()))
// 	}
// }

func removeImage(ctx context.Context, cli *client.Client, c string) {
	if _, err := cli.ImageRemove(ctx, c, image.RemoveOptions{Force: true}); err != nil {
		slog.Error("failed to remove image", slog.String("containerId", c), slog.String("error", err.Error()))
	}
}

// DockerExtractToNPStage processes Docker image tarballs and streams content to NP inputs
type DockerManifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

func DockerExtractToNPStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan types.NpInput {
	logger := logs.NewStageLogger(ctx, opts, "DockerExtractToNPStage")
	out := make(chan types.NpInput)

	go func() {
		defer close(out)

		for imagePath := range in {
			imageFile, err := os.Open(imagePath)
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to open image: %v", err))
				continue
			}
			defer imageFile.Close()

			// Process the outer tar stream
			tr := tar.NewReader(imageFile)
			var manifest []DockerManifest

			// First pass: find and read manifest.json
			for {
				header, err := tr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					logger.Error(fmt.Sprintf("Failed reading tar: %v", err))
					break
				}

				if header.Name == "manifest.json" {
					manifestBytes, err := io.ReadAll(tr)
					if err != nil {
						logger.Error(fmt.Sprintf("Failed reading manifest: %v", err))
						break
					}

					if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
						logger.Error(fmt.Sprintf("Failed parsing manifest: %v", err))
						break
					}
					break
				}
			}

			if len(manifest) == 0 {
				logger.Error("No manifest found in image")
				continue
			}

			// Second pass: process each file and layer
			imageFile.Seek(0, 0) // Reset to start of file
			tr = tar.NewReader(imageFile)

			for {
				header, err := tr.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					logger.Error(fmt.Sprintf("Failed reading tar: %v", err))
					break
				}

				// Skip directories and symlinks
				if header.Typeflag != tar.TypeReg {
					continue
				}

				// Check if this is a layer file
				isLayer := false
				layerName := ""
				for _, m := range manifest {
					for _, layer := range m.Layers {
						if header.Name == layer {
							isLayer = true
							layerName = layer
							break
						}
					}
					if isLayer {
						break
					}
				}

				if isLayer {
					// Process layer tar stream
					layerTr := tar.NewReader(tr)
					for {
						layerHeader, err := layerTr.Next()
						if err == io.EOF {
							break
						}
						if err != nil {
							logger.Error(fmt.Sprintf("Failed reading layer %s: %v", layerName, err))
							break
						}

						// Skip non-regular files
						if layerHeader.Typeflag != tar.TypeReg {
							continue
						}

						// Read file content
						content, err := io.ReadAll(layerTr)
						if err != nil {
							logger.Error(fmt.Sprintf("Failed reading file %s in layer %s: %v", layerHeader.Name, layerName, err))
							continue
						}

						if len(content) == 0 {
							logger.Debug(fmt.Sprintf("Skipping empty file: %s", layerHeader.Name))
							continue
						}

						// Create NP input
						npInput := types.NpInput{
							ContentBase64: base64.StdEncoding.EncodeToString(content),
							Provenance: types.NpProvenance{
								Platform:     "docker",
								ResourceType: "layer",
								ResourceID:   fmt.Sprintf("%s,%s,%s", manifest[0].RepoTags[0], layerName, layerHeader.Name),
							},
						}

						select {
						case <-ctx.Done():
							return
						case out <- npInput:
						}
					}
				} else {
					// Process regular file in image root
					content, err := io.ReadAll(tr)
					if err != nil {
						logger.Error(fmt.Sprintf("Failed reading file %s: %v", header.Name, err))
						continue
					}

					if len(content) == 0 {
						logger.Debug(fmt.Sprintf("Skipping empty file: %s", header.Name))
						continue
					}

					npInput := types.NpInput{
						ContentBase64: base64.StdEncoding.EncodeToString(content),
						Provenance: types.NpProvenance{
							Platform:     "docker",
							ResourceType: "image",
							ResourceID:   manifest[0].RepoTags[0],
							Region:       fmt.Sprintf("file:%s", header.Name),
						},
					}

					select {
					case <-ctx.Done():
						return
					case out <- npInput:
					}
				}
			}
		}
	}()

	return out
}
