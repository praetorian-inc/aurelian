// internal/docker/client.go
package docker

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

// Client wraps Docker CLI operations
type Client struct {
	binaryPath string
}

// NewClient creates a Docker client
func NewClient() (*Client, error) {
	binaryPath, err := exec.LookPath("docker")
	if err != nil {
		return nil, fmt.Errorf("docker not found in PATH: %w", err)
	}
	return &Client{binaryPath: binaryPath}, nil
}

// PullImage pulls an image from a registry
func (c *Client) PullImage(ctx context.Context, image string) error {
	cmd := exec.CommandContext(ctx, c.binaryPath, "pull", image)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// SaveImage saves an image to a tar file
func (c *Client) SaveImage(ctx context.Context, image, outputPath string) error {
	cmd := exec.CommandContext(ctx, c.binaryPath, "save", "-o", outputPath, image)
	return cmd.Run()
}

// ExtractLayers extracts layers from a saved image tar
func (c *Client) ExtractLayers(tarPath, outputDir string) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output dir: %w", err)
	}

	cmd := exec.Command("tar", "-xf", tarPath, "-C", outputDir)
	return cmd.Run()
}

// InspectImage returns image metadata as JSON
func (c *Client) InspectImage(ctx context.Context, image string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, c.binaryPath, "inspect", image)
	return cmd.Output()
}
