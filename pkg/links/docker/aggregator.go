package docker

import (
	"context"
	"log/slog"
	"sync"

	
	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// DockerScanResultAggregator aggregates scan results and outputs summary data
type DockerScanResultAggregator struct {
	*plugin.BaseLink
	mu       sync.Mutex
	images   []ImageScanResult
	findings []types.NPFinding
}

// ImageScanResult represents the result of scanning a single image
type ImageScanResult struct {
	Image      string `json:"image"`
	Status     string `json:"status"`
	LocalPath  string `json:"local_path,omitempty"`
	ExtractDir string `json:"extract_dir,omitempty"`
}

func NewDockerScanResultAggregator(args map[string]any) *DockerScanResultAggregator {
	return &DockerScanResultAggregator{
		BaseLink: plugin.NewBaseLink("docker-scan-aggregator", args),
		images:   make([]ImageScanResult, 0),
		findings: make([]types.NPFinding, 0),
	}
}

func (a *DockerScanResultAggregator) Process(ctx context.Context, input any) ([]any, error) {
	// Handle different input types
	switch v := input.(type) {
	case *types.DockerImage:
		// Track processed images
		result := ImageScanResult{
			Image:     v.Image,
			Status:    "scanned",
			LocalPath: v.LocalPath,
		}
		a.mu.Lock()
		a.images = append(a.images, result)
		a.mu.Unlock()
		slog.Debug("Aggregated image scan result", "image", v.Image)

		// Pass through to next link
		return []any{v}, nil

	case types.NPFinding:
		// Collect findings
		a.mu.Lock()
		a.findings = append(a.findings, v)
		a.mu.Unlock()
		slog.Debug("Aggregated NP finding", "finding_id", v.FindingID)

		// Pass through to outputters
		return []any{v}, nil

	case *types.NPFinding:
		if v == nil {
			return []any{}, nil
		}
		// Collect findings (pointer version)
		a.mu.Lock()
		a.findings = append(a.findings, *v)
		a.mu.Unlock()
		slog.Debug("Aggregated NP finding", "finding_id", v.FindingID)

		// Pass through to outputters
		return []any{v}, nil
	}

	// Pass through anything else
	return []any{input}, nil
}

func (a *DockerScanResultAggregator) Complete(ctx context.Context) ([]any, error) {
	a.mu.Lock()
	imagesCount := len(a.images)
	findingsCount := len(a.findings)
	imagesCopy := make([]ImageScanResult, len(a.images))
	copy(imagesCopy, a.images)
	a.mu.Unlock()

	// Send summary data as the final output
	summary := map[string]any{
		"images_scanned": imagesCount,
		"findings_count": findingsCount,
		"images":         imagesCopy,
	}

	// Log completion
	slog.Info("ECR scan complete",
		"images_scanned", imagesCount,
		"findings", findingsCount)

	// Send the summary - this will go to outputters
	return []any{summary}, nil
}

func (a *DockerScanResultAggregator) Parameters() []plugin.Parameter {
	return nil
}
