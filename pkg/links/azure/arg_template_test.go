package azure

import (
	"context"
	"slices"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/templates"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestARGTemplateLoaderLink(t *testing.T) {
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
			loader, err := templates.NewTemplateLoader(templates.LoadEmbedded)
			require.NoError(t, err)

			if tt.directory != "" {
				err = loader.LoadUserTemplates(tt.directory)
				require.NoError(t, err)
			}

			templatesList := loader.GetTemplates()
			expected := 0
			for _, tmpl := range templatesList {
				if tt.category == "" || slices.Contains(tmpl.Category, tt.category) {
					expected++
				}
			}

			link := NewARGTemplateLoaderLink(tt.directory, tt.category, "")

			results, err := link.Process(context.Background(), tt.sub)
			require.NoError(t, err)

			require.Equal(t, expected, len(results))

			for _, result := range results {
				v, ok := result.(ARGTemplateQueryInput)
				require.True(t, ok, "expected ARGTemplateQueryInput, got %T", result)

				assert.NotNil(t, v.Template)
				assert.Equal(t, tt.sub, v.Subscription)
				if tt.category != "" {
					assert.True(t, slices.Contains(v.Template.Category, tt.category))
				}
			}
		})
	}
}
