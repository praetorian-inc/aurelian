package stages

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/client"
	"github.com/praetorian-inc/nebula/internal/logs"
	"github.com/praetorian-inc/nebula/modules/options"
	"github.com/praetorian-inc/nebula/pkg/types"
)

func DockerExtractorStage(ctx context.Context, opts []*types.Option, in <-chan string) <-chan string {
	logger := logs.NewStageLogger(ctx, opts, "DockerExtractorStage")
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

		// TODO handle container and image cleanup more elegantly with defer
		for c := range in {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}

			logger.Info(fmt.Sprintf("Pulling container: %s", c))

			domain, err := DockerExtractDomain(c)
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to extract domain: %v", err))
				continue
			}

			authConfig := registry.AuthConfig{
				Username:      options.GetOptionByName(options.DockerUserOpt.Name, opts).Value,
				Password:      options.GetOptionByName(options.DockerPasswordOpt.Name, opts).Value,
				ServerAddress: domain,
			}

			var pullOpts image.PullOptions

			if !isPublicImage(c) {
				if _, err := cli.RegistryLogin(ctx, authConfig); err != nil {
					logger.Error(fmt.Sprintf("Failed to login to Docker registry: %v", err))
					continue
				}
				encodedAuthConfig, err := registry.EncodeAuthConfig(authConfig)
				if err != nil {
					logger.Error(fmt.Sprintf("Failed to encode auth config: %v", err))
					continue
				}

				pullOpts = image.PullOptions{
					RegistryAuth: encodedAuthConfig,
				}
			}

			reader, err := cli.ImagePull(ctx, c, pullOpts)
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to pull container %s: %v", c, err))
				continue
			}
			io.Copy(io.Discard, reader)
			reader.Close()

			logger.Info(fmt.Sprintf("Processing container: %s", c))
			// Create container
			resp, err := cli.ContainerCreate(ctx, &container.Config{
				Image: c,
			}, nil, nil, nil, "")
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to create container: %v", err))
				continue
			}
			containerID := resp.ID

			// Get container name for directory
			parts := strings.Split(c, "/")
			name := parts[len(parts)-1]
			name = strings.Split(name, ":")[0] // Remove tag if present

			// Create directory
			if err := os.MkdirAll(filepath.Join(options.GetOptionByName(options.OutputOpt.Name, opts).Value, name), 0755); err != nil {
				logger.Error(fmt.Sprintf("Failed to create directory: %v", err))
				cleanupContainer(ctx, cli, containerID)
				removeImage(ctx, cli, c)
				continue
			}

			// Export container
			reader, err = cli.ContainerExport(ctx, containerID)
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to export container: %v", err))
				cleanupContainer(ctx, cli, containerID)
				removeImage(ctx, cli, c)
				continue
			}

			// Create gzipped tar archive
			archivePath := filepath.Join(options.GetOptionByName(options.OutputOpt.Name, opts).Value, name, name+".tar.gz")
			archive, err := os.Create(archivePath)
			if err != nil {
				logger.Error(fmt.Sprintf("Failed to create archive: %v", err))
				cleanupContainer(ctx, cli, containerID)
				removeImage(ctx, cli, c)
				reader.Close()
				continue
			}

			gw := gzip.NewWriter(archive)
			_, err = io.Copy(gw, reader)
			reader.Close()
			gw.Close()
			archive.Close()

			if err != nil {
				logger.Error(fmt.Sprintf("Failed to write archive: %v", err))
				cleanupContainer(ctx, cli, containerID)
				removeImage(ctx, cli, c)
				continue
			}

			// Extract archive
			if err := extractTarGz(archivePath, filepath.Join(options.GetOptionByName(options.OutputOpt.Name, opts).Value, name)); err != nil {
				logger.Error(fmt.Sprintf("Failed to extract archive: %v", err))
				cleanupContainer(ctx, cli, containerID)
				removeImage(ctx, cli, c)
				continue
			}

			cleanupContainer(ctx, cli, containerID)
			removeImage(ctx, cli, c)

			out <- c
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

func isPublicImage(url string) bool {
	return strings.Contains(url, "public.ecr.aws")
}

func cleanupContainer(ctx context.Context, cli *client.Client, containerID string) {
	if err := cli.ContainerRemove(ctx, containerID, container.RemoveOptions{Force: true}); err != nil {
		slog.Error("failed to remove container", slog.String("containerId", containerID), slog.String("error", err.Error()))
	}
}

func removeImage(ctx context.Context, cli *client.Client, c string) {
	if _, err := cli.ImageRemove(ctx, c, image.RemoveOptions{Force: true}); err != nil {
		slog.Error("failed to remove image", slog.String("containerId", c), slog.String("error", err.Error()))
	}
}

func extractTarGz(archivePath, destDir string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("failed to open archive: %v", err)
	}
	defer file.Close()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %v", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	// Keep track of directories we've created
	createdDirs := make(map[string]bool)

	// Use current user's umask
	defaultDirMode := os.FileMode(0755)  // rwxr-xr-x
	defaultFileMode := os.FileMode(0644) // rw-r--r--

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %v", err)
		}

		// Clean the path to prevent directory traversal
		path := filepath.Clean(filepath.Join(destDir, header.Name))

		// Ensure the path is under the destination directory
		if !strings.HasPrefix(path, filepath.Clean(destDir)) {
			return fmt.Errorf("invalid path in tar: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, defaultDirMode); err != nil {
				return fmt.Errorf("failed to create directory %s: %v", path, err)
			}
			createdDirs[path] = true

		case tar.TypeReg:
			// Ensure parent directory exists
			dir := filepath.Dir(path)
			if !createdDirs[dir] {
				if err := os.MkdirAll(dir, defaultDirMode); err != nil {
					return fmt.Errorf("failed to create parent directory %s: %v", dir, err)
				}
				createdDirs[dir] = true
			}

			// Create file with default permissions
			f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, defaultFileMode)
			if err != nil {
				return fmt.Errorf("failed to create file %s: %v", path, err)
			}

			// Copy file contents
			_, err = io.Copy(f, tr)
			f.Close() // Close before error check to ensure file is closed
			if err != nil {
				return fmt.Errorf("failed to write to file %s: %v", path, err)
			}

		case tar.TypeSymlink:
			// Handle symlinks
			dir := filepath.Dir(path)
			if !createdDirs[dir] {
				if err := os.MkdirAll(dir, defaultDirMode); err != nil {
					return fmt.Errorf("failed to create parent directory %s: %v", dir, err)
				}
				createdDirs[dir] = true
			}

			// Remove existing symlink if it exists
			os.Remove(path)

			if err := os.Symlink(header.Linkname, path); err != nil {
				slog.Error("Failed to create symlink", slog.String("path", path), slog.String("link-name", header.Linkname), slog.String("error", err.Error()))
				// Continue rather than fail for symlink errors
				continue
			}

		case tar.TypeBlock, tar.TypeChar, tar.TypeFifo:
			// Log these special files but don't try to create them
			slog.Debug(fmt.Sprintf("Skipping special file: %s (type: %c)", path, header.Typeflag))
			continue

		default:
			slog.Debug(fmt.Sprintf("Skipping unsupported file type: %c in %s", header.Typeflag, header.Name))
			continue
		}
	}

	return nil
}
