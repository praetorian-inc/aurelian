// Package m365templates defines the M365 CIS check template schema and loader.
package m365templates

import (
	"embed"
	"fmt"
	"path/filepath"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"gopkg.in/yaml.v3"
)

// M365CheckTemplate represents a single CIS benchmark check definition.
type M365CheckTemplate struct {
	ID          string             `yaml:"id"`
	Title       string             `yaml:"title"`
	Service     string             `yaml:"service"`
	Level       string             `yaml:"level"`     // L1, L2
	Profile     string             `yaml:"profile"`   // "E3 Level 1", "E5 Level 2"
	Execution   string             `yaml:"execution"` // Automated, Manual
	Severity    output.RiskSeverity `yaml:"severity"`
	Description string             `yaml:"description"`
	Rationale   string             `yaml:"rationale"`
	Impact      string             `yaml:"impact"`
	Remediation string             `yaml:"remediation"`
	References  []string           `yaml:"references"`
	CISControls []string           `yaml:"cis_controls"`
	Guard       GuardMeta          `yaml:"guard"`
	DataRequirements []string      `yaml:"data_requirements"`
}

// GuardMeta holds metadata for Guard export.
type GuardMeta struct {
	FindingSlug string `yaml:"finding_slug" json:"finding_slug"`
	PhaseTag    string `yaml:"phase_tag"    json:"phase_tag"`
	AssetType   string `yaml:"asset_type"   json:"asset_type"`
	CWE         string `yaml:"cwe,omitempty" json:"cwe,omitempty"`
	CVSSVector  string `yaml:"cvss_vector"  json:"cvss_vector"`
}

// Validate performs basic validation on a check template.
func (t *M365CheckTemplate) Validate() error {
	if t.ID == "" {
		return fmt.Errorf("check ID is required")
	}
	if t.Title == "" {
		return fmt.Errorf("check title is required")
	}
	if t.Severity == "" {
		return fmt.Errorf("check severity is required")
	}
	t.Severity = output.NormalizeSeverity(t.Severity)
	return nil
}

// M365TemplateLoader loads M365 CIS check templates from embedded YAML files.
type M365TemplateLoader struct {
	templates []*M365CheckTemplate
}

// NewM365TemplateLoader creates a loader from an embedded filesystem.
func NewM365TemplateLoader(fs embed.FS) (*M365TemplateLoader, error) {
	loader := &M365TemplateLoader{}

	entries, err := fs.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded templates: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}

		data, err := fs.ReadFile(entry.Name())
		if err != nil {
			return nil, fmt.Errorf("failed to read template %s: %w", entry.Name(), err)
		}

		var tmpl M365CheckTemplate
		if err := yaml.Unmarshal(data, &tmpl); err != nil {
			return nil, fmt.Errorf("failed to parse template %s: %w", entry.Name(), err)
		}

		if err := tmpl.Validate(); err != nil {
			return nil, fmt.Errorf("invalid template %s: %w", entry.Name(), err)
		}

		loader.templates = append(loader.templates, &tmpl)
	}

	return loader, nil
}

// GetTemplates returns all loaded templates.
func (l *M365TemplateLoader) GetTemplates() []*M365CheckTemplate {
	if len(l.templates) == 0 {
		return []*M365CheckTemplate{}
	}
	return l.templates
}

// FilterTemplates returns templates matching the include/exclude filters.
func FilterTemplates(templates []*M365CheckTemplate, include, exclude map[string]bool) []*M365CheckTemplate {
	if include == nil && exclude == nil {
		return templates
	}

	var filtered []*M365CheckTemplate
	for _, t := range templates {
		if exclude != nil && exclude[t.ID] {
			continue
		}
		if include != nil && !include[t.ID] {
			continue
		}
		filtered = append(filtered, t)
	}
	return filtered
}
