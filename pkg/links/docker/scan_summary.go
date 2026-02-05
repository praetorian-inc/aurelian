package docker

import (
	"context"
	"log/slog"
	"sync"

	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/praetorian-inc/aurelian/pkg/outputters"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

// DockerScanSummary collects scan statistics and outputs a summary at completion
type DockerScanSummary struct {
	*plugin.BaseLink
	mu       sync.Mutex
	findings []types.NPFinding
}

func NewDockerScanSummary(args map[string]any) *DockerScanSummary {
	return &DockerScanSummary{
		BaseLink: plugin.NewBaseLink("docker-scan-summary", args),
		findings: make([]types.NPFinding, 0),
	}
}

func (s *DockerScanSummary) Process(ctx context.Context, input any) ([]any, error) {
	// Collect NPFindings
	switch v := input.(type) {
	case types.NPFinding:
		s.mu.Lock()
		s.findings = append(s.findings, v)
		s.mu.Unlock()
		// Pass through to other outputters
		return []any{v}, nil
	case *types.NPFinding:
		if v == nil {
			return []any{}, nil
		}
		s.mu.Lock()
		s.findings = append(s.findings, *v)
		s.mu.Unlock()
		// Pass through to other outputters
		return []any{v}, nil
	}

	// Pass through anything else
	return []any{input}, nil
}

func (s *DockerScanSummary) Complete(ctx context.Context) ([]any, error) {
	s.mu.Lock()
	findingsCount := len(s.findings)
	findingsCopy := make([]types.NPFinding, len(s.findings))
	copy(findingsCopy, s.findings)
	s.mu.Unlock()

	slog.Info("Docker scan completed", "total_findings", findingsCount)

	// Output summary even if no findings
	summary := map[string]any{
		"total_findings": findingsCount,
		"findings":       findingsCopy,
	}

	return []any{outputters.RawOutput{Data: summary}}, nil
}

func (s *DockerScanSummary) Parameters() []plugin.Parameter {
	return nil
}
