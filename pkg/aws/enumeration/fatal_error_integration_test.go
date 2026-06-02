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

// TestFatalError_BadCredentials_AbortsPipeline verifies that fatal credential
// errors (SignatureDoesNotMatch) cause List to return an error instead of
// silently skipping. This is the counterpart to the skip-resilience tests —
// it proves that the blacklist classifier does NOT swallow credential failures.
//
// Uses a fake AWS profile with an invalid secret key. The SDK signs the
// request with the wrong key, AWS responds with SignatureDoesNotMatch,
// and the pipeline must abort.
func TestFatalError_BadCredentials_AbortsPipeline(t *testing.T) {
	profileDir := t.TempDir()
	profileName := "aurelian-test-bad-creds"

	// Write a profile with a syntactically valid access key but wrong secret.
	// AWS will return SignatureDoesNotMatch (fatal, not skippable).
	configContent := "[profile " + profileName + "]\n" +
		"region = us-east-1\n"
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

	// List should return a fatal error — not skip it.
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

	// The error must propagate — bad credentials should NOT be skipped.
	require.Error(t, err, "fatal credential error must propagate, not be skipped")
	assert.Empty(t, collected, "no resources should be returned with bad credentials")

	// SkipReport should be empty — fatal errors are not recorded as skips.
	assert.Equal(t, 0, enumerator.Skipped.Len(),
		"fatal credential errors must NOT appear in SkipReport — they are pipeline-fatal")

	t.Logf("Fatal error propagated correctly: %v", err)
}

// TestFatalError_BadCredentials_StopsPipeline verifies that when multiple
// types are fed through pipeline.Pipe, a fatal credential error on the
// first type stops the entire pipeline — subsequent types are NOT attempted.
func TestFatalError_BadCredentials_StopsPipeline(t *testing.T) {
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

	// Feed multiple types — pipeline should stop after the first fatal error.
	types := pipeline.From(
		"AWS::S3::Bucket",
		"AWS::IAM::Role",
		"AWS::Lambda::Function",
		"AWS::EC2::Instance",
	)
	listed := pipeline.New[output.AWSResource]()
	pipeline.Pipe(types, enumerator.List, listed)

	results, err := listed.Collect()
	require.Error(t, err, "pipeline must abort on fatal credential error")
	assert.Empty(t, results, "no resources should be collected with bad credentials")
	assert.Equal(t, 0, enumerator.Skipped.Len(),
		"fatal errors must NOT be recorded as skips")
	assert.Contains(t, err.Error(), "InvalidClientTokenId",
		"error must surface the credential failure")

	t.Logf("Pipeline aborted correctly: %v", err)
}
