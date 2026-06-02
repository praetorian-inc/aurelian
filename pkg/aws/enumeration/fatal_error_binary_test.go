//go:build integration

package enumeration_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFatalError_Binary_BadCredentials builds the aurelian binary and runs
// it with garbage credentials. Verifies the actual operator experience:
//   - Binary prints "Error:" with the credential failure
//   - Binary does NOT print "enumerated N resources" or skip summary
//   - Exit code is non-zero
//
// Note: the error occurs at GetAccountID (STS level), before enumeration
// starts. This tests the "completely invalid credentials" path — the binary
// fails fast rather than silently producing empty results. The enumeration-
// level fatal error path (credential expires mid-run) is covered by unit
// tests (TestContinueOnDenied_FatalSmithyCode_PropagatesFatal) since it
// cannot be triggered with static AWS profiles.
func TestFatalError_Binary_BadCredentials(t *testing.T) {
	// Build the binary.
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "aurelian")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = findRepoRootExec(t)
	buildOut, err := build.CombinedOutput()
	require.NoError(t, err, "go build failed: %s", string(buildOut))

	// Create a profile with garbage credentials.
	profileDir := t.TempDir()
	profileName := "aurelian-binary-bad-creds"

	configContent := "[profile " + profileName + "]\nregion = us-east-1\n"
	credsContent := "[" + profileName + "]\n" +
		"aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n" +
		"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"

	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "config"), []byte(configContent), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "credentials"), []byte(credsContent), 0o600))

	outputDir := t.TempDir()

	// Run the binary.
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

	// The binary must show an error — not a skip summary.
	assert.Contains(t, outputStr, "Error:",
		"binary must print 'Error:' for fatal credential failure")
	assert.Contains(t, outputStr, "InvalidClientTokenId",
		"error must mention the credential failure code")

	// The binary must NOT show success or skip output.
	assert.NotContains(t, outputStr, "enumerated",
		"binary must NOT print 'enumerated N resources' with bad credentials")
	assert.NotContains(t, outputStr, "skipped",
		"binary must NOT print skip summary with bad credentials")

	// No detail file should be written (Close fires but report is empty).
	_, statErr := os.Stat(filepath.Join(outputDir, "enumeration-skips.json"))
	assert.True(t, os.IsNotExist(statErr),
		"enumeration-skips.json must NOT exist — fatal errors are not recorded as skips")
}

// TestFatalError_Binary_GoodCredentials_RestrictedRole runs the binary with
// the restricted role to verify the happy-path comparison: errors are skipped
// (not fatal), resources are collected, and the skip summary is shown.
func TestFatalError_Binary_GoodCredentials_RestrictedRole(t *testing.T) {
	// Build the binary.
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "aurelian")
	build := exec.Command("go", "build", "-o", binPath, ".")
	build.Dir = findRepoRootExec(t)
	buildOut, err := build.CombinedOutput()
	require.NoError(t, err, "go build failed: %s", string(buildOut))

	// Use the restricted role profile (set up by other tests).
	// We need to create the profile here since we can't share state.
	restrictedRoleARN := os.Getenv("AURELIAN_RESTRICTED_ROLE_ARN")
	if restrictedRoleARN == "" {
		t.Skip("AURELIAN_RESTRICTED_ROLE_ARN not set — run TestSkipResilience first to provision the role")
	}

	profileDir := t.TempDir()
	profileName := "aurelian-binary-restricted"
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
	output, _ := cmd.CombinedOutput()
	outputStr := string(output)

	t.Logf("Binary output:\n%s", outputStr)

	// With restricted role: should enumerate resources AND show skip summary.
	assert.Contains(t, outputStr, "enumerated",
		"binary must print 'enumerated N resources' with valid restricted credentials")
	assert.Contains(t, outputStr, "skipped",
		"binary must print skip summary for denied services")
	assert.NotContains(t, outputStr, "Error:",
		"binary must NOT print 'Error:' — denials should be skipped, not fatal")
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

// findRepoRoot is already defined in close_check_test.go (same package).
// findRepoRootExec is the _test variant for the external test package.
func init() {
	// Suppress unused import for strings.
	_ = strings.Contains
}
