// internal/secrets/noseyparker.go
package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/praetorian-inc/aurelian/pkg/types"
)

// NPScanner wraps NoseyParker CLI for secret detection
type NPScanner struct {
	binaryPath string
	rulesPath  string
	tempDir    string
}

// NewNPScanner creates a scanner with default paths
func NewNPScanner() (*NPScanner, error) {
	// Find noseyparker binary
	binaryPath, err := exec.LookPath("noseyparker")
	if err != nil {
		return nil, fmt.Errorf("noseyparker not found in PATH: %w", err)
	}

	tempDir, err := os.MkdirTemp("", "np-scan-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}

	return &NPScanner{
		binaryPath: binaryPath,
		tempDir:    tempDir,
	}, nil
}

// ScanContent scans provided content for secrets
func (s *NPScanner) ScanContent(ctx context.Context, inputs []types.NpInput) ([]types.NPFinding, error) {
	if len(inputs) == 0 {
		return nil, nil
	}

	// Write inputs to temp files
	inputDir := filepath.Join(s.tempDir, "input")
	if err := os.MkdirAll(inputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create input dir: %w", err)
	}

	for i, input := range inputs {
		filename := filepath.Join(inputDir, fmt.Sprintf("content-%d.txt", i))
		if err := os.WriteFile(filename, []byte(input.Content), 0644); err != nil {
			return nil, fmt.Errorf("failed to write input file: %w", err)
		}
	}

	// Run noseyparker scan
	datastorePath := filepath.Join(s.tempDir, "datastore")
	cmd := exec.CommandContext(ctx, s.binaryPath, "scan",
		"--datastore", datastorePath,
		inputDir,
	)

	if err := cmd.Run(); err != nil {
		// noseyparker returns non-zero if findings exist, check output
	}

	// Get findings as JSON
	reportCmd := exec.CommandContext(ctx, s.binaryPath, "report",
		"--datastore", datastorePath,
		"--format", "json",
	)

	output, err := reportCmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get report: %w", err)
	}

	var findings []types.NPFinding
	if err := json.Unmarshal(output, &findings); err != nil {
		return nil, fmt.Errorf("failed to parse findings: %w", err)
	}

	return findings, nil
}

// Cleanup removes temporary files
func (s *NPScanner) Cleanup() error {
	return os.RemoveAll(s.tempDir)
}
