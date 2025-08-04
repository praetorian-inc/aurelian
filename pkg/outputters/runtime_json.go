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
)

// NamedOutputData represents the structure that should be sent to the RuntimeJSONOutputter
// It contains both the data to be output and the filename to write it to
type NamedOutputData struct {
	OutputFilename string
	Data           any
}

// NewNamedOutputData creates a new NamedOutputData instance
func NewNamedOutputData(data any, filename string) NamedOutputData {
	return NamedOutputData{
		OutputFilename: filename,
		Data:           data,
	}
}

const defaultOutfile = "out.json"

// RuntimeJSONOutputter allows specifying the output file at runtime
// rather than at initialization time
type RuntimeJSONOutputter struct {
	*BaseFileOutputter
	indent  int
	output  []any
	outfile string
}

// NewRuntimeJSONOutputter creates a new RuntimeJSONOutputter
func NewRuntimeJSONOutputter(configs ...cfg.Config) chain.Outputter {
	j := &RuntimeJSONOutputter{}
	j.BaseFileOutputter = NewBaseFileOutputter(j, configs...)
	return j
}

// Initialize sets up the outputter but doesn't open a file yet
func (j *RuntimeJSONOutputter) Initialize() error {
	// Get default output file (can be overridden at runtime)
	outfile, err := cfg.As[string](j.Arg("jsonoutfile"))
	if err != nil {
		outfile = defaultOutfile // Fallback default
	}

	// Create context-rich filename based on available parameters
	if outfile == defaultOutfile {
		contextualName := j.generateContextualFilename()
		if contextualName != "" {
			outfile = filepath.Join("nebula-output", contextualName)
			slog.Debug("using contextual filename", "filename", outfile)
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
		indent = 0
	}
	j.indent = indent

	slog.Debug("initialized runtime JSON outputter", "default_file", j.outfile, "indent", j.indent)
	return nil
}

// Output stores a value in memory for later writing
func (j *RuntimeJSONOutputter) Output(val any) error {
	// Check if we received an OutputData structure
	if outputData, ok := val.(NamedOutputData); ok {
		// If filename is provided, update the output file
		if outputData.OutputFilename != "" && j.outfile == defaultOutfile {
			j.SetOutputFile(outputData.OutputFilename)
		}
		// Add the actual data to our output list
		j.output = append(j.output, outputData.Data)
	} else {
		// Handle the original case where just data is provided
		j.output = append(j.output, val)
	}
	return nil
}

// SetOutputFile allows changing the output file at runtime
func (j *RuntimeJSONOutputter) SetOutputFile(filename string) {
	j.outfile = filename
	// Ensure the new path's directory exists
	if err := j.EnsureOutputPath(filename); err != nil {
		slog.Error("failed to create directory for new output file", "filename", filename, "error", err)
	}
	slog.Debug("changed JSON output file", "filename", filename)
}

// Complete writes all stored outputs to the specified file
func (j *RuntimeJSONOutputter) Complete() error {
	// Check for module-specific parameters one more time at completion
	// in case they're available now but weren't during initialization
	if j.outfile == defaultOutfile || strings.Contains(j.outfile, "nebula-findings-") {
		// Try to generate a contextual filename now that all parameters are available
		contextualName := j.generateContextualFilename()
		if contextualName != "" && !strings.Contains(contextualName, "nebula-findings-") {
			j.outfile = filepath.Join("nebula-output", contextualName)
			slog.Debug("updated to module-specific filename at completion", "filename", j.outfile)
		}
	}

	slog.Debug("writing JSON output", "filename", j.outfile, "entries", len(j.output))

	// Ensure the directory exists (using base functionality)
	if err := j.EnsureOutputPath(j.outfile); err != nil {
		return fmt.Errorf("error creating directory for JSON file %s: %w", j.outfile, err)
	}

	writer, err := os.Create(j.outfile)
	if err != nil {
		return fmt.Errorf("error creating JSON file %s: %w", j.outfile, err)
	}
	defer writer.Close()

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", strings.Repeat(" ", j.indent))

	err = encoder.Encode(j.output)
	if err != nil {
		return err
	}

	message.Success("JSON output written to: %s", j.outfile)
	return nil
}

// generateContextualFilename creates a filename with appropriate context to avoid overwrites
func (j *RuntimeJSONOutputter) generateContextualFilename() string {
	timestamp := time.Now().Format("20060102-150405")
	
	// Check for Azure DevOps organization and project (devops-secrets module)
	devopsOrg, orgErr := cfg.As[string](j.Arg("devops-org"))
	devopsProject, projErr := cfg.As[string](j.Arg("devops-project"))
	
	slog.Debug("checking devops parameters", "devops-org", devopsOrg, "orgErr", orgErr, "devops-project", devopsProject, "projErr", projErr)
	
	if orgErr == nil && devopsOrg != "" {
		if projErr == nil && devopsProject != "" {
			// Both org and project available - use devops-secrets format
			slog.Debug("generating devops-secrets filename", "org", devopsOrg, "project", devopsProject)
			return fmt.Sprintf("devops-secrets-%s-%s.json", devopsOrg, devopsProject)
		} else {
			// Just org available
			slog.Debug("generating devops-secrets filename with org only", "org", devopsOrg)
			return fmt.Sprintf("devops-secrets-%s-all-projects.json", devopsOrg)
		}
	}
	
	// Check for AWS account ID (find-secrets module)
	if accountIds, err := cfg.As[[]string](j.Arg("account-id")); err == nil && len(accountIds) > 0 {
		// Use first account ID if multiple
		accountId := accountIds[0]
		if accountId != "" && accountId != "all" {
			return fmt.Sprintf("aws-find-secrets-%s.json", accountId)
		} else {
			return fmt.Sprintf("aws-find-secrets-multi-account.json")
		}
	}
	
	// Check for Azure subscription (other Azure modules)
	if subscription, err := cfg.As[string](j.Arg("subscription")); err == nil && subscription != "" {
		if subscription == "all" {
			return fmt.Sprintf("azure-findings-all-subscriptions.json")
		} else {
			return fmt.Sprintf("azure-findings-%s.json", subscription)
		}
	}
	
	// No specific context found, use generic name with timestamp
	return fmt.Sprintf("nebula-findings-%s.json", timestamp)
}


// Params defines the parameters accepted by this outputter
func (j *RuntimeJSONOutputter) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[string]("jsonoutfile", "the default file to write the JSON to (can be changed at runtime)").WithDefault(defaultOutfile),
		cfg.NewParam[int]("indent", "the number of spaces to use for the JSON indentation").WithDefault(0),
	}
}
