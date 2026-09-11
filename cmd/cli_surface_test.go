package cmd

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/capability-sdk/pkg/clisurface"
)

var updateGoldens = flag.Bool("update", false,
	"rewrite docs/cli-surface.json, docs/CLI.md and the generated README.md regions from the live cobra tree")

var treeOnce sync.Once

func liveRoot() *cobra.Command {
	treeOnce.Do(initCommands)
	return rootCmd
}

func cliDocs(t *testing.T) *clisurface.Docs {
	t.Helper()
	docs, err := clisurface.New(clisurface.Config{
		RegenerateCommand: "make cli-docs",
		LintedMarkdown:    []string{"README.md"},
		LintedGoDirs:      []string{"cmd", "internal", "pkg"},
	})
	require.NoError(t, err)
	return docs
}

func TestCLISurface(t *testing.T) {
	docs := cliDocs(t)
	cfg := docs.Config()
	root := repoRoot(t)
	live := clisurface.Walk(liveRoot())

	if *updateGoldens {
		require.NoError(t, docs.Write(root, live))
		t.Logf("regenerated %s", strings.Join(docs.GeneratedPaths(), ", "))
		return
	}

	golden, err := os.ReadFile(filepath.Join(root, cfg.JSONPath))
	require.NoErrorf(t, err, "%s is missing; create it with %q", cfg.JSONPath, cfg.RegenerateCommand)
	documented, err := docs.ParseJSON(golden)
	require.NoError(t, err)

	if findings := clisurface.Diff(documented, live); len(findings) > 0 {
		require.Fail(t, "CLI surface drift", docs.Report(findings))
	}

	stale, err := docs.CheckArtifacts(root, live)
	require.NoError(t, err)
	if len(stale) > 0 {
		assert.Fail(t, "generated CLI documentation is stale", stalenessReport(stale))
	}
}

func TestCLISurfaceDocLint(t *testing.T) {
	docs := cliDocs(t)
	root := repoRoot(t)
	allow, err := docs.LoadAllowlist(root)
	require.NoError(t, err)

	issues, scope, err := docs.LintRepo(root, clisurface.Walk(liveRoot()), allow)
	require.NoError(t, err)

	t.Logf("linted %d markdown file(s) [%s] and %d Go file(s) under %d Go dir(s) [%s], with %d token(s) allowlisted; skipped %d entr(y/ies) that are not regular files [%s]",
		len(scope.MarkdownFiles), scopeList(scope.MarkdownFiles),
		len(scope.GoFiles), len(scope.GoDirs), scopeList(scope.GoDirs),
		len(scope.Allowlist.Entries()),
		len(scope.SkippedIrregular), scopeList(scope.SkippedIrregular))

	if len(issues) > 0 {
		assert.Fail(t, "documentation names flags the CLI does not accept", clisurface.LintReport(issues, scope))
	}
}

func TestCLISurfaceGateDetectsRename(t *testing.T) {
	docs := cliDocs(t)
	root := liveRoot()
	documented := clisurface.Walk(root)

	t.Run("renaming a registered flag is reported", func(t *testing.T) {
		whoami := findCommand(t, root, "aws", "recon", "whoami")
		flagObj := whoami.Flags().Lookup("action")
		require.NotNil(t, flagObj, "the fixture flag must exist for this test to mean anything")
		t.Cleanup(func() { flagObj.Name = "action" })
		flagObj.Name = "acton"

		findings := clisurface.Diff(documented, clisurface.Walk(root))

		require.Len(t, findings, 2, "a rename is exactly one removal and one addition, and nothing else:\n%s",
			docs.Report(findings))
		assert.Equal(t, clisurface.FlagRemoved, findings[0].Kind)
		assert.Equal(t, "action", findings[0].Flag)
		assert.Equal(t, "aurelian aws recon whoami", findings[0].Command)
		assert.Equal(t, clisurface.FlagUndocumented, findings[1].Kind)
		assert.Equal(t, "acton", findings[1].Flag)
		assert.Equal(t, "aurelian aws recon whoami", findings[1].Command)
	})

	t.Run("the tree is restored", func(t *testing.T) {
		assert.Empty(t, clisurface.Diff(documented, clisurface.Walk(root)),
			"the rename above must not leak into the rest of the suite")
	})

	t.Run("a document naming a removed flag is reported", func(t *testing.T) {
		empty, err := docs.ParseAllowlist("")
		require.NoError(t, err)

		doc := "Historic note.\n\n```bash\naurelian aws recon whoami --aws-profile default\n```\n"
		issues := docs.LintMarkdown(documented, "docs/example.md", doc, empty)

		require.Len(t, issues, 1)
		assert.Equal(t, "--aws-profile", issues[0].Token)
		assert.Equal(t, "aurelian aws recon whoami", issues[0].Command)
		assert.Contains(t, issues[0].String(),
			`docs/example.md:4: --aws-profile is not a flag of "aurelian aws recon whoami"`)
		assert.Contains(t, issues[0].String(), docs.Config().AllowlistPath,
			"the message says how to allow a deliberate mention")
	})

	t.Run("a backticked flag name in prose is reported", func(t *testing.T) {
		empty, err := docs.ParseAllowlist("")
		require.NoError(t, err)

		doc := "Authenticate with `--aws-profile` before recon.\n"
		issues := docs.LintMarkdown(documented, "docs/example.md", doc, empty)

		require.Len(t, issues, 1)
		assert.Equal(t, "--aws-profile", issues[0].Token)
		assert.Empty(t, issues[0].Command, "a prose token is checked against the whole surface")
		assert.Contains(t, issues[0].String(),
			"docs/example.md:1: --aws-profile is not a flag of any command in the CLI")
	})

	t.Run("an unbackticked prose mention is not read at all", func(t *testing.T) {
		empty, err := docs.ParseAllowlist("")
		require.NoError(t, err)

		doc := "Authenticate with --aws-profile before recon.\n"
		assert.Empty(t, docs.LintMarkdown(documented, "docs/example.md", doc, empty))
	})

	t.Run("the allowlist suppresses a deliberate mention", func(t *testing.T) {
		allow, err := docs.ParseAllowlist("--aws-profile # AWS CLI flag, not an aurelian flag; the migration note names it\n")
		require.NoError(t, err)

		doc := "Historic note: `--aws-profile`.\n\n```bash\naurelian aws recon whoami --aws-profile default\n```\n"
		assert.Empty(t, docs.LintMarkdown(documented, "docs/example.md", doc, allow),
			"the allowlist must suppress the token in a fenced invocation and in prose alike")
	})
}

func findCommand(t *testing.T, cmd *cobra.Command, names ...string) *cobra.Command {
	t.Helper()
	for _, name := range names {
		var next *cobra.Command
		for _, child := range cmd.Commands() {
			if child.Name() == name {
				next = child
				break
			}
		}
		require.NotNilf(t, next, "%q has no subcommand %q", cmd.CommandPath(), name)
		cmd = next
	}
	return cmd
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	root, err := clisurface.FindRepoRoot(wd)
	require.NoError(t, err)
	return root
}

func stalenessReport(stale []clisurface.Staleness) string {
	lines := make([]string, 0, len(stale))
	for i := range stale {
		lines = append(lines, stale[i].String())
	}
	return strings.Join(lines, "\n")
}

func scopeList(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}
