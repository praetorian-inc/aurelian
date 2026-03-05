package templates

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"gopkg.in/yaml.v3"
)

//go:embed *.yaml
var EmbeddedTemplates embed.FS

// TemplateLoader loads templates from both embedded files and optional user-supplied directory
type TemplateLoader struct {
	templates []*ARGQueryTemplate
}

// NewTemplateLoader creates a new template loader that reads YAML templates from the given embed.FS.
func NewTemplateLoader(fs embed.FS) (*TemplateLoader, error) {
	loader := &TemplateLoader{}

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
			return nil, fmt.Errorf("failed to read embedded template %s: %w", entry.Name(), err)
		}

		var template ARGQueryTemplate
		if err := yaml.Unmarshal(data, &template); err != nil {
			return nil, fmt.Errorf("failed to parse embedded template %s: %w", entry.Name(), err)
		}

		if err := ValidateTemplate(&template); err != nil {
			return nil, fmt.Errorf("invalid embedded template %s: %w", entry.Name(), err)
		}

		loader.templates = append(loader.templates, &template)
	}

	return loader, nil
}

// LoadUserTemplates loads additional templates from a user-specified directory
func (l *TemplateLoader) LoadUserTemplates(templateDir string) error {
	if templateDir == "" {
		return nil // No user templates to load
	}

	// Check if directory exists
	dirInfo, err := os.Stat(templateDir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("template directory '%s' does not exist", templateDir)
		}
		return fmt.Errorf("failed to access template directory: %v", err)
	}

	if !dirInfo.IsDir() {
		return fmt.Errorf("'%s' is not a directory", templateDir)
	}

	// Find all .yaml files in template directory
	files, err := filepath.Glob(filepath.Join(templateDir, "*.yaml"))
	if err != nil {
		return fmt.Errorf("failed to list template files: %v", err)
	}

	// Load each template file
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read template file %s: %v", file, err)
		}

		var template ARGQueryTemplate
		if err := yaml.Unmarshal(data, &template); err != nil {
			return fmt.Errorf("failed to parse template file %s: %v", file, err)
		}

		// Validate template
		if err := ValidateTemplate(&template); err != nil {
			return fmt.Errorf("invalid template %s: %v", file, err)
		}

		// Add to templates list
		l.templates = append(l.templates, &template)
	}

	return nil
}

// GetTemplates returns all loaded templates
func (l *TemplateLoader) GetTemplates() []*ARGQueryTemplate {
	if len(l.templates) == 0 {
		return []*ARGQueryTemplate{}
	}
	return l.templates
}

// ValidateTemplate performs basic validation and normalizes severity to lowercase.
func ValidateTemplate(template *ARGQueryTemplate) error {
	if template.ID == "" {
		return fmt.Errorf("template ID is required")
	}
	if template.Name == "" {
		return fmt.Errorf("template name is required")
	}
	if template.Query == "" {
		return fmt.Errorf("template query is required")
	}
	if template.Severity == "" {
		return fmt.Errorf("template severity is required")
	}
	template.Severity = output.NormalizeSeverity(template.Severity)
	return nil
}
