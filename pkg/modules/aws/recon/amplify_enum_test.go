package recon

import (
	"os"
	"slices"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAmplifyEnumRegistration(t *testing.T) {
	mod, ok := plugin.Get(plugin.PlatformAWS, plugin.CategoryRecon, "amplify-discover")
	require.True(t, ok, "amplify-discover module should be registered")
	assert.Equal(t, "amplify-discover", mod.ID())
	assert.Equal(t, "AWS Amplify Branch Discovery", mod.Name())
}

func TestNormalizeDistributionID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"d2zslx120k55ro", "d2zslx120k55ro"},
		{"D2ZSLX120K55RO", "d2zslx120k55ro"},
		{"d2zslx120k55ro.cloudfront.net", "d2zslx120k55ro"},
		{"https://d2zslx120k55ro.cloudfront.net", "d2zslx120k55ro"},
		{"https://d2zslx120k55ro.cloudfront.net/", "d2zslx120k55ro"},
		{"http://d2zslx120k55ro.cloudfront.net/some/path", "d2zslx120k55ro"},
		{"main.d2zslx120k55ro.amplifyapp.com", "main.d2zslx120k55ro"},
		{"  d2zslx120k55ro  ", "d2zslx120k55ro"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.want, normalizeDistributionID(tt.input))
		})
	}
}

func TestBuildBranchList(t *testing.T) {
	t.Run("defaults only when no user branches", func(t *testing.T) {
		branches := buildBranchList(nil)
		assert.Equal(t, defaultBranchNames, branches)
	})

	t.Run("user branches merged with defaults", func(t *testing.T) {
		branches := buildBranchList([]string{"custom-feature", "my-branch"})
		assert.Contains(t, branches, "main")
		assert.Contains(t, branches, "master")
		assert.Contains(t, branches, "custom-feature")
		assert.Contains(t, branches, "my-branch")
	})

	t.Run("duplicates not added", func(t *testing.T) {
		branches := buildBranchList([]string{"main", "dev", "new-branch"})
		mainCount := 0
		for _, b := range branches {
			if b == "main" {
				mainCount++
			}
		}
		assert.Equal(t, 1, mainCount, "main should appear exactly once")
		assert.Contains(t, branches, "new-branch")
	})

	t.Run("empty and whitespace-only branches skipped", func(t *testing.T) {
		branches := buildBranchList([]string{"", "  ", "valid"})
		assert.Contains(t, branches, "valid")
		assert.False(t, slices.Contains(branches, ""), "empty branch must be skipped")
		assert.False(t, slices.Contains(branches, "  "), "whitespace branch must be skipped")
	})
}

func TestLoadDistributions(t *testing.T) {
	t.Run("from file deduplicates and skips comments", func(t *testing.T) {
		content := "d1abc2def3gh\nhttps://d9xyz456.cloudfront.net\n# comment line\n\nd1abc2def3gh\n"
		f, err := os.CreateTemp(t.TempDir(), "distributions-*.txt")
		require.NoError(t, err)
		_, err = f.WriteString(content)
		require.NoError(t, err)
		require.NoError(t, f.Close())

		params := AmplifyEnumParams{DistributionsFile: f.Name()}
		dists, err := params.loadDistributions()
		require.NoError(t, err)
		require.Len(t, dists, 2)
		assert.Equal(t, "d1abc2def3gh", normalizeDistributionID(dists[0]))
		assert.Equal(t, "d9xyz456", normalizeDistributionID(dists[1]))
	})

	t.Run("merges file and flag", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "distributions-*.txt")
		require.NoError(t, err)
		_, err = f.WriteString("d1fromfile\n")
		require.NoError(t, err)
		require.NoError(t, f.Close())

		params := AmplifyEnumParams{
			Distributions:     []string{"d2fromflag"},
			DistributionsFile: f.Name(),
		}
		dists, err := params.loadDistributions()
		require.NoError(t, err)
		require.Len(t, dists, 2)
		assert.Equal(t, "d2fromflag", normalizeDistributionID(dists[0]))
		assert.Equal(t, "d1fromfile", normalizeDistributionID(dists[1]))
	})

	t.Run("missing file returns error", func(t *testing.T) {
		params := AmplifyEnumParams{DistributionsFile: "/nonexistent/path.txt"}
		_, err := params.loadDistributions()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "opening distributions file")
	})

	t.Run("neither flag nor file is empty", func(t *testing.T) {
		params := AmplifyEnumParams{}
		dists, err := params.loadDistributions()
		require.NoError(t, err)
		assert.Empty(t, dists)
	})
}
