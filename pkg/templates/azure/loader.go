package azure

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/templates"
	"gopkg.in/yaml.v3"
)

//go:embed *.yaml
var embeddedTemplates embed.FS

// Loader loads ARG query templates from embedded files and optional user directories.
type Loader struct {
	templates []*templates.ARGQueryTemplate
}

// NewLoader creates a Loader pre-populated with all embedded YAML templates.
func NewLoader() (*Loader, error) {
	l := &Loader{}

	entries, err := embeddedTemplates.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded azure templates: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}

		data, err := embeddedTemplates.ReadFile(entry.Name())
		if err != nil {
			return nil, fmt.Errorf("failed to read embedded template %s: %w", entry.Name(), err)
		}

		var tmpl templates.ARGQueryTemplate
		if err := yaml.Unmarshal(data, &tmpl); err != nil {
			return nil, fmt.Errorf("failed to parse template %s: %w", entry.Name(), err)
		}

		if err := validateTemplate(&tmpl); err != nil {
			return nil, fmt.Errorf("invalid template %s: %w", entry.Name(), err)
		}

		l.templates = append(l.templates, &tmpl)
	}

	return l, nil
}

// LoadUserTemplates loads additional templates from a user-specified directory.
func (l *Loader) LoadUserTemplates(dir string) error {
	if dir == "" {
		return nil
	}

	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("template directory %q: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%q is not a directory", dir)
	}

	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return fmt.Errorf("failed to list template files: %w", err)
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("failed to read template %s: %w", file, err)
		}

		var tmpl templates.ARGQueryTemplate
		if err := yaml.Unmarshal(data, &tmpl); err != nil {
			return fmt.Errorf("failed to parse template %s: %w", file, err)
		}

		if err := validateTemplate(&tmpl); err != nil {
			return fmt.Errorf("invalid template %s: %w", file, err)
		}

		l.templates = append(l.templates, &tmpl)
	}

	return nil
}

// GetTemplates returns all loaded templates.
func (l *Loader) GetTemplates() []*templates.ARGQueryTemplate {
	return l.templates
}

func validateTemplate(t *templates.ARGQueryTemplate) error {
	if t.ID == "" {
		return fmt.Errorf("template ID is required")
	}
	if t.Name == "" {
		return fmt.Errorf("template name is required")
	}
	if t.Query == "" {
		return fmt.Errorf("template query is required")
	}
	if t.Severity == "" {
		return fmt.Errorf("template severity is required")
	}
	t.Severity = output.NormalizeSeverity(t.Severity)
	return nil
}
