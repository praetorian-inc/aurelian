package configurationscan

import (
	"embed"

	"github.com/praetorian-inc/aurelian/pkg/templates"
)

//go:embed *.yaml
var embeddedTemplates embed.FS

// NewLoader creates a TemplateLoader pre-populated with all embedded
// configuration scan YAML templates.
func NewLoader() (*templates.TemplateLoader, error) {
	return templates.NewTemplateLoader(embeddedTemplates)
}
