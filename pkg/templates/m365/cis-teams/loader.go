package cisteams

import (
	"embed"

	m365templates "github.com/praetorian-inc/aurelian/pkg/templates/m365"
)

//go:embed *.yaml
var embeddedTemplates embed.FS

// NewLoader creates a template loader pre-populated with all embedded
// CIS Teams check templates.
func NewLoader() (*m365templates.M365TemplateLoader, error) {
	return m365templates.NewM365TemplateLoader(embeddedTemplates)
}
