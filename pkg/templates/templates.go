package templates

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"gopkg.in/yaml.v3"
)

// ARGQueryTemplate represents a single Azure Resource Graph query template
type ARGQueryTemplate struct {
    ID          string   `yaml:"id"`          
    Name        string   `yaml:"name"`        
    Description string   `yaml:"description"`  
    Severity    string   `yaml:"severity"`     
    Query       string   `yaml:"query"`       
    Category    string   `yaml:"category"`    
    References  []string `yaml:"references"` 
    TriageNotes string   `yaml:"triageNotes,omitempty"`
}

// ARGQueryResult represents a standardized result from an ARG query
type ARGQueryResult struct {
    TemplateID      string                 `json:"templateId"`
    TemplateDetails *ARGQueryTemplate      `json:"templateDetails"`
    Name            string                 `json:"name"`
    ResourceID      string                 `json:"resourceId"`
    ResourceName    string                 `json:"resourceName"`
    ResourceType    string                 `json:"resourceType"`
    Location        string                 `json:"location"`
    SubscriptionID  string                 `json:"subscriptionId"`
    Properties      map[string]interface{} `json:"properties,omitempty"`
}
// ARGTemplateLoader handles loading and validating ARG query templates
type ARGTemplateLoader struct {
	Templates []*ARGQueryTemplate
}

//go:embed *.yaml
var EmbeddedTemplates embed.FS

// TemplateLoader loads templates from both embedded files and optional user-supplied directory
type TemplateLoader struct {
	templates []*ARGQueryTemplate
}

// NewTemplateLoader creates a new template loader and loads embedded templates
func NewTemplateLoader() (*TemplateLoader, error) {
	loader := &TemplateLoader{}
	
	// First load embedded templates
	entries, err := EmbeddedTemplates.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded templates: %v", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".yaml" {
			data, err := EmbeddedTemplates.ReadFile(entry.Name())
			if err != nil {
				return nil, fmt.Errorf("failed to read embedded template %s: %v", entry.Name(), err)
			}

			var template ARGQueryTemplate
			if err := yaml.Unmarshal(data, &template); err != nil {
				return nil, fmt.Errorf("failed to parse embedded template %s: %v", entry.Name(), err)
			}

			// Validate template
			if err := validateTemplate(&template); err != nil {
				return nil, fmt.Errorf("invalid embedded template %s: %v", entry.Name(), err)
			}

			loader.templates = append(loader.templates, &template)
		}
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
		if err := validateTemplate(&template); err != nil {
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

// validateTemplate performs basic validation of a template
func validateTemplate(template *ARGQueryTemplate) error {
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
	return nil
}