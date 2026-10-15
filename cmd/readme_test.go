package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReplaceReadmeMarked(t *testing.T) {
	t.Run("missing begin", func(t *testing.T) {
		_, err := replaceReadmeMarked("no markers here", "modules", "body")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "<!-- autogen:modules -->")
	})

	t.Run("missing end", func(t *testing.T) {
		_, err := replaceReadmeMarked("<!-- autogen:modules -->body only", "modules", "body")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "<!-- /autogen:modules -->")
	})

	t.Run("replaces trimmed body with wrapping newlines", func(t *testing.T) {
		in := "before <!-- autogen:modules -->\n  old  \n<!-- /autogen:modules --> after"
		got, err := replaceReadmeMarked(in, "modules", "\nnew\n")
		require.NoError(t, err)
		assert.Equal(t, "before <!-- autogen:modules -->\nnew\n<!-- /autogen:modules --> after", got)
	})
}

func TestShortReadmeDescription(t *testing.T) {
	t.Run("collapses whitespace", func(t *testing.T) {
		assert.Equal(t, "a b c", shortReadmeDescription("a   b\n\tc"))
	})

	t.Run("escapes pipes", func(t *testing.T) {
		assert.Equal(t, "has \\| pipe", shortReadmeDescription("has | pipe"))
	})

	t.Run("leaves short text unchanged", func(t *testing.T) {
		assert.Equal(t, "short", shortReadmeDescription("short"))
	})

	t.Run("truncates on word boundary and suffixes ellipsis", func(t *testing.T) {
		words := strings.Repeat("word ", 30)
		got := shortReadmeDescription(words)
		assert.True(t, strings.HasSuffix(got, "..."), got)
		assert.LessOrEqual(t, len(strings.TrimSuffix(got, "...")), 120)
		assert.NotContains(t, strings.TrimSuffix(got, "..."), "  ")
		cut := strings.TrimSuffix(got, "...")
		assert.NotEqual(t, ' ', cut[len(cut)-1])
	})
}

func TestApplyReadme(t *testing.T) {
	input := strings.Join([]string{
		"| **Amazon Web Services (AWS)** | `aws`, `amazon` | <!-- autogen:count:aws -->16<!-- /autogen:count:aws --> | old |",
		"| **Microsoft Azure** | `azure`, `az` | <!-- autogen:count:azure -->6<!-- /autogen:count:azure --> | old |",
		"| **Google Cloud Platform (GCP)** | `gcp`, `google` | <!-- autogen:count:gcp -->4<!-- /autogen:count:gcp --> | old |",
		"",
		"## Modules",
		"",
		"<!-- autogen:modules -->",
		"### AWS Reconnaissance",
		"",
		"| Module | Description |",
		"|--------|-------------|",
		"| `find-secrets` | HANDWRITTEN DESC |",
		"| `gone-module` | Should be dropped |",
		"",
		"### AWS Analysis",
		"",
		"| Module | Description |",
		"|--------|-------------|",
		"| `expand-actions` | Old expand |",
		"<!-- /autogen:modules -->",
		"",
	}, "\n")

	live := []readmeGroup{
		{
			Platform: plugin.PlatformAWS,
			Category: plugin.CategoryRecon,
			Mods: []readmeMod{
				{ID: "find-secrets", Description: "REGISTRY DESC MUST NOT WIN"},
				{ID: "new-recon", Description: "A  brand   new module"},
			},
		},
		{
			Platform: plugin.PlatformAWS,
			Category: plugin.CategoryAnalyze,
			Mods: []readmeMod{
				{ID: "expand-actions", Description: "registry expand"},
				{ID: "graph", Description: "Surfaces privilege-escalation paths"},
			},
		},
		{
			Platform: plugin.PlatformAzure,
			Category: plugin.CategoryRecon,
			Mods: []readmeMod{
				{ID: "apim-audit", Description: "Audits APIM"},
			},
		},
	}

	got, err := applyReadme(input, live)
	require.NoError(t, err)

	assert.Contains(t, got, "<!-- autogen:count:aws -->4<!-- /autogen:count:aws -->")
	assert.Contains(t, got, "<!-- autogen:count:azure -->1<!-- /autogen:count:azure -->")
	assert.Contains(t, got, "<!-- autogen:count:gcp -->0<!-- /autogen:count:gcp -->")
	assert.Contains(t, got, "| `find-secrets` | HANDWRITTEN DESC |")
	assert.NotContains(t, got, "REGISTRY DESC MUST NOT WIN")
	assert.NotContains(t, got, "gone-module")
	assert.Contains(t, got, "| `new-recon` | A brand new module |")
	assert.Contains(t, got, "| `expand-actions` | Old expand |")
	assert.Contains(t, got, "| `graph` | Surfaces privilege-escalation paths |")
	assert.Contains(t, got, "### Azure Reconnaissance")
	assert.Contains(t, got, "| `apim-audit` | Audits APIM |")

	again, err := applyReadme(got, live)
	require.NoError(t, err)
	assert.Equal(t, got, again)
}

func TestApplyReadmeRealInventory(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "README.md"))
	require.NoError(t, err)

	live := collectReadmeModules()
	got, err := applyReadme(string(raw), live)
	require.NoError(t, err)

	assert.Contains(t, got, "`apim-audit`")
	assert.Contains(t, got, "`apim-cross-tenant`")
	assert.Contains(t, got, "`graph`")
	assert.Contains(t, got, "`find-secrets` | Enumerates resources, extracts content from 30+ source types, scans with Titus")
	assert.Contains(t, got, "<!-- autogen:count:aws -->22<!-- /autogen:count:aws -->")
	assert.Contains(t, got, "<!-- autogen:count:azure -->8<!-- /autogen:count:azure -->")
	assert.Contains(t, got, "<!-- autogen:count:gcp -->4<!-- /autogen:count:gcp -->")

	again, err := applyReadme(got, live)
	require.NoError(t, err)
	assert.Equal(t, got, again)
}
