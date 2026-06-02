//go:build integration

package enumeration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFatalError_InvalidCredentials_FailsFast verifies that completely invalid
// credentials cause an immediate error — not silent empty results.
//
// The error occurs at GetAccountID (STS GetCallerIdentity), BEFORE any
// enumeration starts. This is the "garbage credentials" path.
//
// The enumeration-level fatal error path is tested by:
//   - Unit: TestEnumerator_List_FatalError_StopsPipeline (mock ExpiredToken)
//   - Binary: TestFatalError_Binary_EnumerationLevel (build tag + restricted role)
func TestFatalError_InvalidCredentials_FailsFast(t *testing.T) {
	profileDir := t.TempDir()
	profileName := "aurelian-test-bad-creds"

	configContent := "[profile " + profileName + "]\nregion = us-east-1\n"
	credsContent := "[" + profileName + "]\n" +
		"aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n" +
		"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"

	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "config"), []byte(configContent), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "credentials"), []byte(credsContent), 0o600))

	enumerator := NewEnumerator(plugin.AWSCommonRecon{
		AWSReconBase: plugin.AWSReconBase{
			Profile:    profileName,
			ProfileDir: profileDir,
			OutputDir:  t.TempDir(),
		},
		Regions:     []string{"us-east-1"},
		Concurrency: 1,
	})
	defer enumerator.Close()

	// Single List call — fails at STS, not at enumeration.
	out := pipeline.New[output.AWSResource]()
	var collected []output.AWSResource
	done := make(chan struct{})
	go func() {
		defer close(done)
		for r := range out.Range() {
			collected = append(collected, r)
		}
	}()

	err := enumerator.List("AWS::S3::Bucket", out)
	out.Close()
	<-done

	require.Error(t, err, "invalid credentials must produce an error")
	assert.Contains(t, err.Error(), "InvalidClientTokenId")
	assert.Empty(t, collected)
	assert.Equal(t, 0, enumerator.Skipped.Len(),
		"credential errors must NOT appear in SkipReport")
}

// TestFatalError_InvalidCredentials_PipelineFailsFast verifies that a
// pipeline of multiple types also fails fast with invalid credentials.
// Same STS-level failure — included to confirm pipeline.Pipe propagates
// the error correctly.
func TestFatalError_InvalidCredentials_PipelineFailsFast(t *testing.T) {
	profileDir := t.TempDir()
	profileName := "aurelian-test-bad-creds-pipeline"

	configContent := "[profile " + profileName + "]\nregion = us-east-1\n"
	credsContent := "[" + profileName + "]\n" +
		"aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n" +
		"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"

	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "config"), []byte(configContent), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, "credentials"), []byte(credsContent), 0o600))

	enumerator := NewEnumerator(plugin.AWSCommonRecon{
		AWSReconBase: plugin.AWSReconBase{
			Profile:    profileName,
			ProfileDir: profileDir,
			OutputDir:  t.TempDir(),
		},
		Regions:     []string{"us-east-1"},
		Concurrency: 1,
	})
	defer enumerator.Close()

	types := pipeline.From(
		"AWS::S3::Bucket",
		"AWS::IAM::Role",
		"AWS::Lambda::Function",
		"AWS::EC2::Instance",
	)
	listed := pipeline.New[output.AWSResource]()
	pipeline.Pipe(types, enumerator.List, listed)

	results, err := listed.Collect()
	require.Error(t, err, "invalid credentials must abort pipeline")
	assert.Contains(t, err.Error(), "InvalidClientTokenId")
	assert.Empty(t, results)
	assert.Equal(t, 0, enumerator.Skipped.Len())
}
