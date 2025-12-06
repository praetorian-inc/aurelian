package docker

import (
	"log/slog"
	"sync"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	janusTypes "github.com/praetorian-inc/janus-framework/pkg/types"
)

// DockerScanSummary collects scan statistics and outputs a summary at completion
type DockerScanSummary struct {
	*chain.Base
	mu       sync.Mutex
	findings []janusTypes.NPFinding
}

func NewDockerScanSummary(configs ...cfg.Config) chain.Link {
	s := &DockerScanSummary{
		findings: make([]janusTypes.NPFinding, 0),
	}
	s.Base = chain.NewBase(s, configs...)
	return s
}

func (s *DockerScanSummary) Process(input any) error {
	// Collect NPFindings
	switch v := input.(type) {
	case janusTypes.NPFinding:
		s.mu.Lock()
		s.findings = append(s.findings, v)
		s.mu.Unlock()
		// Pass through to other outputters
		return s.Send(v)
	case *janusTypes.NPFinding:
		if v == nil {
			return nil
		}
		s.mu.Lock()
		s.findings = append(s.findings, *v)
		s.mu.Unlock()
		// Pass through to other outputters
		return s.Send(v)
	}

	// Pass through anything else
	return s.Send(input)
}

func (s *DockerScanSummary) Complete() error {
	s.mu.Lock()
	findingsCount := len(s.findings)
	findingsCopy := make([]janusTypes.NPFinding, len(s.findings))
	copy(findingsCopy, s.findings)
	s.mu.Unlock()

	slog.Info("Docker scan completed", "total_findings", findingsCount)

	// Output summary even if no findings
	summary := map[string]any{
		"total_findings": findingsCount,
		"findings":       findingsCopy,
	}

	return s.Send(summary)
}
