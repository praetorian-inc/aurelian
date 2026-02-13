package testutils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	awssts "github.com/praetorian-inc/aurelian/pkg/aws/sts"
	"github.com/stretchr/testify/require"
)

const (
	integrationAccountID = "411435703965"
	integrationRoleARN   = "arn:aws:iam::411435703965:role/OrganizationAccountAccessRole"
)

type IntegrationConfig struct {
	Profile    string
	ProfileDir string
}

func SetupIntegrationConfig(t *testing.T) IntegrationConfig {
	t.Helper()

	require.NoError(t, env.Load())

	profile := env.Get("INTEGRATION_AWS_PROFILE")
	require.NotEmpty(t, profile, "INTEGRATION_AWS_PROFILE is unset")

	sourceDir, err := resolveCurrentProfileDir()
	require.NoError(t, err)

	sourceCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
		Profile:    profile,
		ProfileDir: sourceDir,
		Region:     "us-east-1",
	})
	require.NoError(t, err)

	accountID, err := awshelpers.GetAccountId(sourceCfg)
	require.NoError(t, err)

	if accountID == integrationAccountID {
		cfg := IntegrationConfig{Profile: profile, ProfileDir: sourceDir}
		t.Cleanup(func() {
			require.NoError(t, cleanupIntegrationConfig(cfg), "failed to clean up integration profile")
		})

		return cfg
	}

	creds, err := awssts.AssumeRoleCredentials(sourceCfg, integrationRoleARN, "aurelian-integration-test-session")
	require.NoError(t, err)

	tempDir, err := os.MkdirTemp("", "aurelian-integration-aws-*")
	require.NoError(t, err)

	tempProfile := randomProfileName()
	if err := writeTempAWSProfile(tempDir, tempProfile, creds, sourceCfg.Region); err != nil {
		_ = os.RemoveAll(tempDir)
		t.Fatalf("failed to write temporary AWS profile: %v", err)
	}

	cfg := IntegrationConfig{Profile: tempProfile, ProfileDir: tempDir}
	t.Cleanup(func() {
		require.NoError(t, cleanupIntegrationConfig(cfg), "failed to clean up integration profile")
	})

	return cfg
}

func cleanupIntegrationConfig(cfg IntegrationConfig) error {
	if cfg.ProfileDir == "" {
		return nil
	}

	isTemp, err := isInTempDir(cfg.ProfileDir)
	if err != nil {
		return err
	}
	if !isTemp {
		return nil
	}

	return os.RemoveAll(cfg.ProfileDir)
}

func resolveCurrentProfileDir() (string, error) {
	if credsFile := env.Get("AWS_SHARED_CREDENTIALS_FILE"); credsFile != "" {
		return filepath.Dir(credsFile), nil
	}
	if configFile := env.Get("AWS_CONFIG_FILE"); configFile != "" {
		return filepath.Dir(configFile), nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, ".aws"), nil
}

func writeTempAWSProfile(dir, profile string, creds *ststypes.Credentials, region string) error {
	credentialsPath := filepath.Join(dir, "credentials")
	configPath := filepath.Join(dir, "config")

	credentialsContent := fmt.Sprintf("[%s]\naws_access_key_id = %s\naws_secret_access_key = %s\naws_session_token = %s\n", profile, aws.ToString(creds.AccessKeyId), aws.ToString(creds.SecretAccessKey), aws.ToString(creds.SessionToken))
	if err := os.WriteFile(credentialsPath, []byte(credentialsContent), 0o600); err != nil {
		return err
	}

	if region == "" {
		region = "us-east-1"
	}
	configContent := fmt.Sprintf("[profile %s]\nregion = %s\n", profile, region)
	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
		return err
	}

	return nil
}

func randomProfileName() string {
	randomBytes := make([]byte, 6)
	if _, err := rand.Read(randomBytes); err != nil {
		return fmt.Sprintf("integration-temp-%d", os.Getpid())
	}
	return fmt.Sprintf("integration-temp-%s", hex.EncodeToString(randomBytes))
}

func isInTempDir(dir string) (bool, error) {
	absPath, err := filepath.Abs(dir)
	if err != nil {
		return false, err
	}

	tempPath := filepath.Clean(os.TempDir())
	absPath = filepath.Clean(absPath)

	if absPath == tempPath {
		return true, nil
	}

	return strings.HasPrefix(absPath, tempPath+string(filepath.Separator)), nil
}

func init() {
	_ = env.Load()
}
