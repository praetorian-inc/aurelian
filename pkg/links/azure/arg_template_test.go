package azure

import (
	"testing"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/templates"
	"github.com/stretchr/testify/assert"
)

func TestNewARGTemplateLoaderLink(t *testing.T) {
	tests := []struct {
		name      string
		sub       string
		directory string
		category  string
	}{
		{
			name:      "No filters",
			sub:       "sub1",
			directory: "",
			category:  "",
		},
		{
			name:      "With category filter",
			sub:       "sub1",
			directory: "",
			category:  "Public Access",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Dynamically determine expected results
			loader, _ := templates.NewTemplateLoader()
			if tt.directory != "" {
				_ = loader.LoadUserTemplates(tt.directory)
			}
			templatesList := loader.GetTemplates()
			expected := 0
			for _, t := range templatesList {
				if tt.category == "" || t.Category == tt.category {
					expected += 1
				}
			}

			link := NewARGTemplateLoaderLink(
				cfg.WithArg("template-dir", tt.directory),
				cfg.WithArg("category", tt.category),
			)

			c := chain.NewChain(link)
			c.Send(tt.sub)
			c.Close()

			results := 0
			for v, ok := chain.RecvAs[ARGTemplateQueryInput](c); ok; v, ok = chain.RecvAs[ARGTemplateQueryInput](c) {
				if tt.category != "" && v.Template.Category != tt.category {
					continue // Only count/assert those matching the filter
				}
				results++
				assert.NotNil(t, v.Template)
				assert.Equal(t, tt.sub, v.Subscription)
				if tt.category != "" {
					assert.Equal(t, tt.category, v.Template.Category)
				}
			}
			assert.NoError(t, c.Error())
			assert.Equal(t, expected, results)
		})
	}
}
