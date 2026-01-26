package outputters

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

const defaultSecurityOutfile = "security-findings.json"

// SecurityFindingsJSONOutputter is designed specifically for security analysis modules
// that output structured security findings rather than generic resource listings
type SecurityFindingsJSONOutputter struct {
	*BaseFileOutputter
	indent   int
	findings []any // Store security findings in their native format
	outfile  string
}

// NewSecurityFindingsJSONOutputter creates a new SecurityFindingsJSONOutputter
func NewSecurityFindingsJSONOutputter(configs ...cfg.Config) chain.Outputter {
	j := &SecurityFindingsJSONOutputter{
		findings: make([]any, 0),
	}
	j.BaseFileOutputter = NewBaseFileOutputter(j, configs...)
	return j
}

// Initialize sets up the outputter
func (j *SecurityFindingsJSONOutputter) Initialize() error {
	// Get output directory
	outputDir, err := cfg.As[string](j.Arg("output"))
	if err != nil {
		outputDir = "nebula-output" // Fallback default
	}

	// Get default output file (can be overridden at runtime)
	outfile, err := cfg.As[string](j.Arg("outfile"))
	if err != nil {
		outfile = defaultSecurityOutfile // Fallback default
	}

	// If custom filename provided, prepend with output directory
	if outfile != defaultSecurityOutfile {
		outfile = filepath.Join(outputDir, outfile)
		slog.Debug("using custom security findings filename", "filename", outfile)
	} else {
		// Create context-rich filename based on available parameters
		contextualName := j.generateSecurityFilename()
		if contextualName != "" {
			outfile = filepath.Join(outputDir, contextualName)
			slog.Debug("using contextual security filename", "filename", outfile)
		} else {
			outfile = filepath.Join(outputDir, outfile)
		}
	}

	j.outfile = outfile

	// Ensure output directory exists early to prevent runtime errors
	if err := j.EnsureOutputPath(j.outfile); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Get indentation setting
	indent, err := cfg.As[int](j.Arg("indent"))
	if err != nil {
		indent = 2 // Default to pretty-printed JSON for security findings
	}
	j.indent = indent

	slog.Debug("initialized security findings JSON outputter", "file", j.outfile, "indent", j.indent)
	return nil
}

// Output stores security findings in their native format
func (j *SecurityFindingsJSONOutputter) Output(val any) error {
	// Store security findings directly without modification
	j.findings = append(j.findings, val)
	slog.Debug("stored security finding", "type", fmt.Sprintf("%T", val))
	return nil
}

// Complete writes all stored security findings to the specified file
func (j *SecurityFindingsJSONOutputter) Complete() error {
	// Update filename at completion if needed
	if filepath.Base(j.outfile) == defaultSecurityOutfile || strings.Contains(j.outfile, "security-findings") {
		outputDir, err := cfg.As[string](j.Arg("output"))
		if err != nil {
			outputDir = "nebula-output"
		}

		contextualName := j.generateSecurityFilename()
		if contextualName != "" && !strings.Contains(contextualName, "security-findings") {
			j.outfile = filepath.Join(outputDir, contextualName)
			slog.Debug("updated to module-specific security filename", "filename", j.outfile)
		}
	}

	slog.Debug("writing security findings JSON",
		"filename", j.outfile,
		"findings_count", len(j.findings))

	// Ensure the directory exists
	if err := j.EnsureOutputPath(j.outfile); err != nil {
		return fmt.Errorf("error creating directory for security findings file %s: %w", j.outfile, err)
	}

	writer, err := os.Create(j.outfile)
	if err != nil {
		return fmt.Errorf("error creating security findings file %s: %w", j.outfile, err)
	}
	defer writer.Close()

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", strings.Repeat(" ", j.indent))

	// Output findings directly - if single finding, output as object; if multiple, as array
	var outputData any
	if len(j.findings) == 1 {
		outputData = j.findings[0]
	} else {
		outputData = j.findings
	}

	err = encoder.Encode(outputData)
	if err != nil {
		return fmt.Errorf("error encoding security findings: %w", err)
	}

	message.Success("Security findings written to: %s", j.outfile)
	return nil
}

// generateSecurityFilename creates a filename appropriate for security findings
func (j *SecurityFindingsJSONOutputter) generateSecurityFilename() string {
	timestamp := time.Now().Format("20060102-150405")

	// Get module name if provided
	moduleName, moduleErr := cfg.As[string](j.Arg("module-name"))
	if moduleErr != nil || moduleName == "" {
		moduleName = "security-findings"
		slog.Debug("module-name not found, using fallback", "fallback", moduleName)
	}

	// Try to determine platform context
	// GCP parameters
	if orgs, err := cfg.As[[]string](j.Arg("org")); err == nil && len(orgs) > 0 && orgs[0] != "" {
		orgId := orgs[0]
		slog.Debug("Found GCP org, generating GCP security filename", "org", orgId, "module", moduleName)
		return fmt.Sprintf("%s-gcp-%s.json", moduleName, orgId)
	}

	if project, err := cfg.As[string](j.Arg("project")); err == nil && project != "" {
		slog.Debug("Found GCP project, generating GCP security filename", "project", project, "module", moduleName)
		return fmt.Sprintf("%s-gcp-%s.json", moduleName, project)
	}

	// AWS parameters
	if _, err := cfg.As[string](j.Arg("profile")); err == nil {
		slog.Debug("Found AWS profile, generating AWS security filename", "module", moduleName)
		return fmt.Sprintf("%s-aws.json", moduleName)
	}

	// Azure parameters
	if subscriptions, err := cfg.As[[]string](j.Arg("subscription")); err == nil && len(subscriptions) > 0 && subscriptions[0] != "" {
		slog.Debug("Found Azure subscription, generating Azure security filename", "subscription", subscriptions[0], "module", moduleName)
		return fmt.Sprintf("%s-azure.json", moduleName)
	}

	// Fallback to timestamp
	slog.Debug("No platform parameters found, using timestamp fallback for security findings")
	return fmt.Sprintf("%s-%s.json", moduleName, timestamp)
}

// Params defines the parameters accepted by this outputter
func (j *SecurityFindingsJSONOutputter) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[string]("outfile", "the file to write security findings to").WithDefault(defaultSecurityOutfile),
		cfg.NewParam[int]("indent", "the number of spaces to use for JSON indentation").WithDefault(2),
		cfg.NewParam[string]("module-name", "the name of the security module for dynamic file naming"),
		options.OutputDir(),
	}
}