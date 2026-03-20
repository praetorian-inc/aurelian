package secrets

import (
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Integration tests verify that titus rule behavior (EXAMPLE exclusion) and
// ignore pattern filtering (botocore examples) work end-to-end through the
// Aurelian scanner pipeline.

// ---------------------------------------------------------------------------
// EXAMPLE key exclusion — titus pattern_requirements.ignore_if_contains
// ---------------------------------------------------------------------------

func TestIntegration_ExampleAWSKeysExcluded(t *testing.T) {
	s := startScanner(t)

	// The EXAMPLE exclusion (pattern_requirements.ignore_if_contains) applies
	// to the AWS-specific rules (np.aws.*). We verify that EXAMPLE access key
	// IDs produce no np.aws.* matches.
	cases := []struct {
		name    string
		content string
	}{
		{
			name:    "AKIA EXAMPLE key",
			content: "aws_access_key_id=AKIAIOSFODNN7EXAMPLE",
		},
		{
			name:    "ASIA EXAMPLE session key",
			content: "aws_access_key_id=ASIADEADEXAMPLEEEEEE",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := pipeline.New[SecretScanResult]()
			go func() {
				defer out.Close()
				require.NoError(t, s.Scan(output.ScanInput{
					Content:      []byte(tc.content),
					ResourceID:   "arn:aws:lambda:us-east-1:123456789012:function:demo",
					ResourceType: "AWS::Lambda::Function",
					Region:       "us-east-1",
					AccountID:    "123456789012",
					Label:        "config/credentials",
				}, out))
			}()
			items, err := out.Collect()
			require.NoError(t, err)

			for _, item := range items {
				assert.NotContains(t, item.Match.RuleID, "np.aws.",
					"EXAMPLE key must not trigger AWS rules, but got %s", item.Match.RuleID)
			}
		})
	}
}

func TestIntegration_RealAWSKeysDetected(t *testing.T) {
	s := startScanner(t)

	cases := []struct {
		name    string
		content string
	}{
		{
			name:    "AKIA non-example key",
			content: "aws_access_key_id=AKIADEADBEEFDEADBEEF",
		},
		{
			name:    "secret key non-example",
			content: "aws_secret_access_key=abcdefghijklmnopqrstuvwxyz0123456789ABCD",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := pipeline.New[SecretScanResult]()
			go func() {
				defer out.Close()
				require.NoError(t, s.Scan(output.ScanInput{
					Content:      []byte(tc.content),
					ResourceID:   "arn:aws:lambda:us-east-1:123456789012:function:demo",
					ResourceType: "AWS::Lambda::Function",
					Region:       "us-east-1",
					AccountID:    "123456789012",
					Label:        "config/credentials",
				}, out))
			}()
			items, err := out.Collect()
			require.NoError(t, err)
			assert.NotEmpty(t, items, "non-EXAMPLE keys must produce findings")
		})
	}
}

// ---------------------------------------------------------------------------
// Botocore example file ignore — ignore.conf: **/botocore/data/**/examples-1.json
// ---------------------------------------------------------------------------

func TestIntegration_BotocoreExampleFilesIgnored(t *testing.T) {
	s := startScanner(t)

	// Real-world botocore paths that appear inside Lambda ZIPs with vendored
	// Python dependencies. These contain example AWS keys that would otherwise
	// trigger false positives.
	ignoredPaths := []string{
		"botocore/data/kms/2014-11-01/examples-1.json",
		"botocore/data/s3/2006-03-01/examples-1.json",
		"botocore/data/iam/2010-05-08/examples-1.json",
		"lib/python3.11/site-packages/botocore/data/sts/2011-06-15/examples-1.json",
		"vendor/botocore/data/ec2/2016-11-15/examples-1.json",
	}

	// Content that would normally match if not ignored.
	content := []byte(`{"examples":{"AssumeRole":[{"input":{"RoleArn":"arn:aws:iam::123456789012:role/demo","RoleSessionName":"test"},"output":{"Credentials":{"AccessKeyId":"AKIADEADBEEFDEADBEEF","SecretAccessKey":"abcdefghijklmnopqrstuvwxyz0123456789ABCD"}}}]}`)

	for _, path := range ignoredPaths {
		t.Run(path, func(t *testing.T) {
			out := pipeline.New[SecretScanResult]()
			go func() {
				defer out.Close()
				require.NoError(t, s.Scan(output.ScanInput{
					Content:        content,
					ResourceID:     "arn:aws:lambda:us-east-1:123456789012:function:demo",
					ResourceType:   "AWS::Lambda::Function",
					Region:         "us-east-1",
					AccountID:      "123456789012",
					Label:          path,
					PathFilterable: true,
				}, out))
			}()
			items, err := out.Collect()
			require.NoError(t, err)
			assert.Empty(t, items, "botocore example file %s must be ignored", path)
		})
	}
}

func TestIntegration_BotocoreServiceFilesNotIgnored(t *testing.T) {
	s := startScanner(t)

	// Service files at non-vendored paths (no site-packages prefix) should NOT
	// be ignored — only examples-1.json is excluded by the botocore pattern.
	// Note: paths under **/site-packages/botocore/** ARE ignored by the
	// vendored SDK pattern, so we only test non-vendored botocore paths here.
	allowedPaths := []string{
		"botocore/data/kms/2014-11-01/service-2.json",
		"botocore/data/s3/2006-03-01/paginators-1.json",
	}

	content := []byte(`{"AccessKeyId":"AKIADEADBEEFDEADBEEF","SecretAccessKey":"abcdefghijklmnopqrstuvwxyz0123456789ABCD"}`)

	for _, path := range allowedPaths {
		t.Run(path, func(t *testing.T) {
			out := pipeline.New[SecretScanResult]()
			go func() {
				defer out.Close()
				require.NoError(t, s.Scan(output.ScanInput{
					Content:        content,
					ResourceID:     "arn:aws:lambda:us-east-1:123456789012:function:demo",
					ResourceType:   "AWS::Lambda::Function",
					Region:         "us-east-1",
					AccountID:      "123456789012",
					Label:          path,
					PathFilterable: true,
				}, out))
			}()
			items, err := out.Collect()
			require.NoError(t, err)
			assert.NotEmpty(t, items, "botocore service file %s must NOT be ignored", path)
		})
	}
}

// ---------------------------------------------------------------------------
// Vendored SDK ignore patterns
// ---------------------------------------------------------------------------

func TestIntegration_VendoredSDKPathsIgnored(t *testing.T) {
	s := startScanner(t)

	ignoredPaths := []string{
		"site-packages/botocore/auth.py",
		"site-packages/boto3/session.py",
		"node_modules/@aws-sdk/client-s3/dist/index.js",
	}

	content := []byte(`aws_secret_access_key=abcdefghijklmnopqrstuvwxyz0123456789ABCD`)

	for _, path := range ignoredPaths {
		t.Run(path, func(t *testing.T) {
			out := pipeline.New[SecretScanResult]()
			go func() {
				defer out.Close()
				require.NoError(t, s.Scan(output.ScanInput{
					Content:        content,
					ResourceID:     "arn:aws:lambda:us-east-1:123456789012:function:demo",
					ResourceType:   "AWS::Lambda::Function",
					Region:         "us-east-1",
					AccountID:      "123456789012",
					Label:          path,
					PathFilterable: true,
				}, out))
			}()
			items, err := out.Collect()
			require.NoError(t, err)
			assert.Empty(t, items, "vendored SDK path %s must be ignored", path)
		})
	}
}
