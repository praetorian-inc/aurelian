package outputters

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/internal/message"
	"github.com/praetorian-inc/nebula/pkg/templates"
	"github.com/praetorian-inc/tabularium/pkg/model/model"
)

// ARGScanOutput represents the complete output structure with template metadata
type ARGScanOutput struct {
	Metadata ARGScanMetadata `json:"metadata"`
	Findings []any           `json:"findings"`
}

// ARGScanMetadata contains information about the scan and template details
type ARGScanMetadata struct {
	ScanDate    time.Time                                `json:"scanDate"`
	TotalCount  int                                      `json:"totalFindings"`
	Templates   map[string]*templates.ARGQueryTemplate   `json:"templates"`
}

// ARGScanJSONOutputter is specialized for ARG scan results with template metadata
type ARGScanJSONOutputter struct {
	*BaseFileOutputter
	indent     int
	findings   []any
	templates  map[string]*templates.ARGQueryTemplate
	outfile    string
	scanDate   time.Time
}

// NewARGScanJSONOutputter creates a new ARGScanJSONOutputter
func NewARGScanJSONOutputter(configs ...cfg.Config) chain.Outputter {
	j := &ARGScanJSONOutputter{
		templates: make(map[string]*templates.ARGQueryTemplate),
		scanDate:  time.Now(),
	}
	j.BaseFileOutputter = NewBaseFileOutputter(j, configs...)
	return j
}

// Initialize sets up the outputter
func (j *ARGScanJSONOutputter) Initialize() error {
	// Get output directory and filename (reuse logic from RuntimeJSONOutputter)
	outputDir, err := cfg.As[string](j.Arg("output"))
	if err != nil {
		outputDir = "nebula-output"
	}

	// Generate contextual filename
	moduleName, err := cfg.As[string](j.Arg("module-name"))
	if err != nil {
		moduleName = "arg-scan"
	}

	// Generate Azure-specific filename
	if subscriptions, err := cfg.As[[]string](j.Arg("subscription")); err == nil && len(subscriptions) > 0 {
		subscription := subscriptions[0]
		if subscription == "all" {
			j.outfile = fmt.Sprintf("%s/%s-all-subscriptions.json", outputDir, moduleName)
		} else {
			j.outfile = fmt.Sprintf("%s/%s-%s.json", outputDir, moduleName, subscription)
		}
	} else {
		j.outfile = fmt.Sprintf("%s/%s.json", outputDir, moduleName)
	}

	// Ensure directory exists
	if err := j.EnsureOutputPath(j.outfile); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Get indentation setting
	indent, err := cfg.As[int](j.Arg("indent"))
	if err != nil {
		indent = 2 // Default to 2 for readability
	}
	j.indent = indent

	return nil
}

// Output processes findings and collects template metadata
func (j *ARGScanJSONOutputter) Output(val any) error {
	// Handle NamedOutputData wrapper
	if outputData, ok := val.(NamedOutputData); ok {
		return j.processFinding(outputData.Data)
	}
	return j.processFinding(val)
}

// processFinding extracts template information and stores the finding
func (j *ARGScanJSONOutputter) processFinding(finding any) error {
	j.findings = append(j.findings, finding)

	// Try to extract template information from different types
	var templateID string

	// Check if it's an AzureResource from the model package (value or pointer)
	if azureResource, ok := finding.(model.AzureResource); ok {
		if azureResource.Properties != nil {
			if id, exists := azureResource.Properties["templateID"]; exists {
				if templateIDStr, ok := id.(string); ok {
					templateID = templateIDStr
				}
			}
		}
	} else if azureResource, ok := finding.(*model.AzureResource); ok {
		if azureResource.Properties != nil {
			if id, exists := azureResource.Properties["templateID"]; exists {
				if templateIDStr, ok := id.(string); ok {
					templateID = templateIDStr
				}
			}
		}
	} else if findingMap, ok := finding.(map[string]any); ok {
		if properties, ok := findingMap["properties"].(map[string]any); ok {
			if id, ok := properties["templateID"].(string); ok {
				templateID = id
			}
		}
	}

	if templateID != "" {
		// Load template details if we haven't seen this template ID before
		if _, exists := j.templates[templateID]; !exists {
			j.loadTemplateDetails(templateID)
		}
	}

	return nil
}

// loadTemplateDetails loads template metadata for a given template ID
func (j *ARGScanJSONOutputter) loadTemplateDetails(templateID string) {
	// Initialize template loader
	loader, err := templates.NewTemplateLoader()
	if err != nil {
		message.Error("Failed to initialize template loader: %v", err)
		j.templates[templateID] = nil
		return
	}

	// Try to get template directory from args (optional)
	if templateDir, err := cfg.As[string](j.Arg("template-dir")); err == nil && templateDir != "" {
		if err := loader.LoadUserTemplates(templateDir); err != nil {
			message.Error("Failed to load user templates from %s: %v", templateDir, err)
		}
	}

	// Find the template by ID
	templatesList := loader.GetTemplates()
	for _, template := range templatesList {
		if template.ID == templateID {
			j.templates[templateID] = template
			return
		}
	}

	// Template not found - this shouldn't happen for valid templateIDs
	message.Warning("Template with ID '%s' not found among %d available templates", templateID, len(templatesList))
	j.templates[templateID] = nil
}

// SetTemplateDetails allows the ARG scan module to provide template metadata
func (j *ARGScanJSONOutputter) SetTemplateDetails(templates map[string]*templates.ARGQueryTemplate) {
	j.templates = templates
}

// Complete writes the structured output with template metadata
func (j *ARGScanJSONOutputter) Complete() error {
	// Create the complete output structure
	output := ARGScanOutput{
		Metadata: ARGScanMetadata{
			ScanDate:   j.scanDate,
			TotalCount: len(j.findings),
			Templates:  j.templates,
		},
		Findings: j.findings,
	}

	// Write to file
	writer, err := os.Create(j.outfile)
	if err != nil {
		return fmt.Errorf("error creating JSON file %s: %w", j.outfile, err)
	}
	defer writer.Close()

	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", strings.Repeat(" ", j.indent))

	// Go's JSON encoder handles all special character escaping automatically
	err = encoder.Encode(output)
	if err != nil {
		return fmt.Errorf("error encoding JSON: %w", err)
	}

	message.Success("ARG scan JSON output written to: %s", j.outfile)
	return nil
}

// Params defines the parameters accepted by this outputter
func (j *ARGScanJSONOutputter) Params() []cfg.Param {
	return []cfg.Param{
		cfg.NewParam[int]("indent", "the number of spaces to use for the JSON indentation").WithDefault(2),
		cfg.NewParam[string]("module-name", "the name of the module for dynamic file naming"),
		cfg.NewParam[string]("output", "output directory"),
	}
}