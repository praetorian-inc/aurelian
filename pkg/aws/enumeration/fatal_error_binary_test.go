//go:build integration

package enumeration_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/aurelian/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFatalError_Binary_EnumerationLevel builds the binary with the
// fatal_test_mode tag (which adds AccessDeniedException to fatalErrorCodes),
// then runs it with the restricted role. STS succeeds (valid credentials),
// but the first AccessDeniedException during enumeration (e.g. DynamoDB
// via CloudControl) is now fatal — the pipeline must abort.
//
// This tests the complete chain at binary level: fatal error during
// enumeration → classifier → dispatcher → pipeline abort → CLI error.
func TestFatalError_Binary_EnumerationLevel(t *testing.T) {
	fixture := testutil.NewAWSFixture(t, "aws/recon/list")
	fixture.Setup()

	restrictedRoleARN := fixture.Output("restricted_role_arn")
	require.NotEmpty(t, restrictedRoleARN)

	// Build binary with fatal_test_mode tag.
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "aurelian")
	build := exec.Command("go", "build", "-tags", "fatal_test_mode", "-o", binPath, ".")
	build.Dir = findRepoRootExec(t)
	buildOut, err := build.CombinedOutput()
	require.NoError(t, err, "go build failed: %s", string(buildOut))

	// Set up restricted role profile.
	profileDir := t.TempDir()
	profileName := "aurelian-binary-fatal-enum"
	sourceProfile := os.Getenv("AWS_PROFILE")
	if sourceProfile == "" {
		sourceProfile = "default"
	}

	homeDir, _ := os.UserHomeDir()
	origConfig, _ := os.ReadFile(filepath.Join(homeDir, ".aws", "config"))
	origCreds, _ := os.ReadFile(filepath.Join(homeDir, ".aws", "credentials"))

	configContent := string(origConfig) + "\n[profile " + profileName + "]\n" +
		"role_arn = " + restrictedRoleARN + "\n" +
		"source_profile = " + sourceProfile + "\nregion = us-east-1\n"
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "config"), []byte(configContent), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "credentials"), origCreds, 0o600))

	outputDir := t.TempDir()

	// Run — STS works, but first AccessDeniedException is now fatal.
	cmd := exec.Command(binPath,
		"aws", "recon", "list-all",
		"--profile", profileName,
		"--profile-dir", profileDir,
		"--regions", "us-east-1",
		"--scan-type", "summary",
		"--output-dir", outputDir,
		"--no-color",
	)
	cmd.Env = append(os.Environ(),
		"AWS_CONFIG_FILE="+filepath.Join(profileDir, "config"),
		"AWS_SHARED_CREDENTIALS_FILE="+filepath.Join(profileDir, "credentials"),
	)
	output, runErr := cmd.CombinedOutput()
	outputStr := string(output)

	t.Logf("Binary output:\n%s", outputStr)
	t.Logf("Exit code error: %v", runErr)

	// 1. Binary must show a fatal error.
	assert.Contains(t, outputStr, "Error:",
		"binary must abort when AccessDeniedException is fatal at enumeration level")
	assert.Contains(t, outputStr, "AccessDeniedException",
		"error must mention the denied operation")

	// 2. Pipeline must have stopped — no resources enumerated, no skip summary.
	// NOTE: when LAB-3942 (graceful shutdown) is implemented, these assertions
	// will need updating — the binary will show partial results and a skip
	// summary even on fatal errors.
	assert.NotContains(t, outputStr, "enumerated",
		"binary must NOT show 'enumerated N resources' — pipeline should have aborted")
	assert.NotContains(t, outputStr, "skipped",
		"binary must NOT show skip summary — pipeline should have aborted before Close()")

	// 3. Exit code must be non-zero.
	assert.Error(t, runErr, "binary must exit with non-zero code on fatal error")

	// 4. No output file — the pipeline aborted before writing results.
	entries, _ := os.ReadDir(outputDir)
	for _, e := range entries {
		assert.NotContains(t, e.Name(), "list-all",
			"no list-all output file should exist — pipeline aborted before writing")
	}
}

func findRepoRootExec(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root")
		}
		dir = parent
	}
}
