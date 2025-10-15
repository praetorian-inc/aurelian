package docker

import (
	"log/slog"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	dockerTypes "github.com/praetorian-inc/janus-framework/pkg/types/docker"
	janusTypes "github.com/praetorian-inc/janus-framework/pkg/types"
)

// DockerScanResultAggregator aggregates scan results and outputs summary data
type DockerScanResultAggregator struct {
	*chain.Base
	images   []ImageScanResult
	findings []janusTypes.NPFinding
}

// ImageScanResult represents the result of scanning a single image
type ImageScanResult struct {
	Image      string `json:"image"`
	Status     string `json:"status"`
	LocalPath  string `json:"local_path,omitempty"`
	ExtractDir string `json:"extract_dir,omitempty"`
}

func NewDockerScanResultAggregator(configs ...cfg.Config) chain.Link {
	a := &DockerScanResultAggregator{
		images:   make([]ImageScanResult, 0),
		findings: make([]janusTypes.NPFinding, 0),
	}
	a.Base = chain.NewBase(a, configs...)
	return a
}

func (a *DockerScanResultAggregator) Process(input any) error {
	// Handle different input types
	switch v := input.(type) {
	case *dockerTypes.DockerImage:
		// Track processed images
		result := ImageScanResult{
			Image:     v.Image,
			Status:    "scanned",
			LocalPath: v.LocalPath,
		}
		a.images = append(a.images, result)
		slog.Debug("Aggregated image scan result", "image", v.Image)

		// Pass through to next link
		return a.Send(v)

	case janusTypes.NPFinding:
		// Collect findings
		a.findings = append(a.findings, v)
		slog.Debug("Aggregated NP finding", "finding_id", v.FindingID)

		// Pass through to outputters
		return a.Send(v)

	case *janusTypes.NPFinding:
		// Collect findings (pointer version)
		a.findings = append(a.findings, *v)
		slog.Debug("Aggregated NP finding", "finding_id", v.FindingID)

		// Pass through to outputters
		return a.Send(v)
	}

	// Pass through anything else
	return a.Send(input)
}

func (a *DockerScanResultAggregator) Complete() error {
	// Send summary data as the final output
	summary := map[string]any{
		"images_scanned":  len(a.images),
		"findings_count":  len(a.findings),
		"images":          a.images,
	}

	// Log completion
	slog.Info("ECR scan complete",
		"images_scanned", len(a.images),
		"findings", len(a.findings))

	// Send the summary - this will go to outputters
	return a.Send(summary)
}
