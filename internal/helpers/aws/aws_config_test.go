package helpers

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func fakeLoader(capture *config.LoadOptions) ConfigLoader {
	return func(ctx context.Context, optFns ...func(*config.LoadOptions) error) (aws.Config, error) {
		opts := config.LoadOptions{}
		for _, fn := range optFns {
			if err := fn(&opts); err != nil {
				return aws.Config{}, err
			}
		}
		*capture = opts
		// Return config with region from opts
		return aws.Config{Region: opts.Region}, nil
	}
}

// errorLoader creates a fake ConfigLoader that returns the given error
func errorLoader(err error) ConfigLoader {
	return func(ctx context.Context, optFns ...func(*config.LoadOptions) error) (aws.Config, error) {
		return aws.Config{}, err
	}
}

// TestNewAWSConfig_RegionPassedThrough verifies explicit region is used
func TestNewAWSConfig_RegionPassedThrough(t *testing.T) {
	var captured config.LoadOptions
	loader := fakeLoader(&captured)

	input := AWSConfigInput{
		Region: "eu-west-1",
	}

	cfg, err := newAWSConfigWith(loader, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if cfg.Region != "eu-west-1" {
		t.Errorf("expected region eu-west-1, got %s", cfg.Region)
	}

	if captured.Region != "eu-west-1" {
		t.Errorf("expected captured region eu-west-1, got %s", captured.Region)
	}
}

// TestNewAWSConfig_EmptyRegionDefaultsToUSEast1 verifies default region behavior
func TestNewAWSConfig_EmptyRegionDefaultsToUSEast1(t *testing.T) {
	var captured config.LoadOptions
	loader := fakeLoader(&captured)

	input := AWSConfigInput{
		Region: "", // empty
	}

	cfg, err := newAWSConfigWith(loader, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if cfg.Region != "us-east-1" {
		t.Errorf("expected default region us-east-1, got %s", cfg.Region)
	}

	if captured.Region != "us-east-1" {
		t.Errorf("expected captured region us-east-1, got %s", captured.Region)
	}
}

// TestNewAWSConfig_ProfileSet verifies profile is passed to config
func TestNewAWSConfig_ProfileSet(t *testing.T) {
	var captured config.LoadOptions
	loader := fakeLoader(&captured)

	input := AWSConfigInput{
		Region:  "us-west-2",
		Profile: "dev-profile",
	}

	_, err := newAWSConfigWith(loader, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if captured.SharedConfigProfile != "dev-profile" {
		t.Errorf("expected SharedConfigProfile 'dev-profile', got '%s'", captured.SharedConfigProfile)
	}
}

// TestNewAWSConfig_ProfileEmpty verifies no profile option when empty
func TestNewAWSConfig_ProfileEmpty(t *testing.T) {
	var captured config.LoadOptions
	loader := fakeLoader(&captured)

	input := AWSConfigInput{
		Region:  "us-west-2",
		Profile: "", // empty
	}

	_, err := newAWSConfigWith(loader, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// When Profile is empty, SharedConfigProfile should not be set
	if captured.SharedConfigProfile != "" {
		t.Errorf("expected no SharedConfigProfile, got '%s'", captured.SharedConfigProfile)
	}
}

// TestNewAWSConfig_ProfileDirSet verifies shared config/credentials files
func TestNewAWSConfig_ProfileDirSet(t *testing.T) {
	var captured config.LoadOptions
	loader := fakeLoader(&captured)

	input := AWSConfigInput{
		Region:     "us-west-2",
		ProfileDir: "/custom/aws/dir",
	}

	_, err := newAWSConfigWith(loader, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Check SharedConfigFiles
	expectedConfig := "/custom/aws/dir/config"
	if len(captured.SharedConfigFiles) != 1 || captured.SharedConfigFiles[0] != expectedConfig {
		t.Errorf("expected SharedConfigFiles [%s], got %v", expectedConfig, captured.SharedConfigFiles)
	}

	// Check SharedCredentialsFiles
	expectedCreds := "/custom/aws/dir/credentials"
	if len(captured.SharedCredentialsFiles) != 1 || captured.SharedCredentialsFiles[0] != expectedCreds {
		t.Errorf("expected SharedCredentialsFiles [%s], got %v", expectedCreds, captured.SharedCredentialsFiles)
	}
}

// TestNewAWSConfig_ProfileDirEmpty verifies no shared config files when empty
func TestNewAWSConfig_ProfileDirEmpty(t *testing.T) {
	var captured config.LoadOptions
	loader := fakeLoader(&captured)

	input := AWSConfigInput{
		Region:     "us-west-2",
		ProfileDir: "", // empty
	}

	_, err := newAWSConfigWith(loader, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// When ProfileDir is empty, no shared config/credentials files should be set
	if len(captured.SharedConfigFiles) > 0 {
		t.Errorf("expected no SharedConfigFiles, got %v", captured.SharedConfigFiles)
	}

	if len(captured.SharedCredentialsFiles) > 0 {
		t.Errorf("expected no SharedCredentialsFiles, got %v", captured.SharedCredentialsFiles)
	}
}

// TestNewAWSConfig_LoadOptionFnsApplied verifies custom load options are applied
func TestNewAWSConfig_LoadOptionFnsApplied(t *testing.T) {
	var captured config.LoadOptions
	loader := fakeLoader(&captured)

	customOptionCalled := false
	customOption := func(opts *config.LoadOptions) error {
		customOptionCalled = true
		return nil
	}

	input := AWSConfigInput{
		Region:        "us-west-2",
		LoadOptionFns: []func(*config.LoadOptions) error{customOption},
	}

	_, err := newAWSConfigWith(loader, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !customOptionCalled {
		t.Error("expected custom LoadOptionFn to be called, but it wasn't")
	}
}

// TestNewAWSConfig_LoaderErrorPropagated verifies loader errors are returned
func TestNewAWSConfig_LoaderErrorPropagated(t *testing.T) {
	expectedErr := errors.New("loader failed")
	loader := errorLoader(expectedErr)

	input := AWSConfigInput{
		Region: "us-west-2",
	}

	_, err := newAWSConfigWith(loader, input)
	if err != expectedErr {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}
}

// TestNewAWSConfig_AllParametersTogether verifies all parameters work together
func TestNewAWSConfig_AllParametersTogether(t *testing.T) {
	var captured config.LoadOptions
	loader := fakeLoader(&captured)

	customOptionCalled := false
	customOption := func(opts *config.LoadOptions) error {
		customOptionCalled = true
		return nil
	}

	input := AWSConfigInput{
		Region:        "ap-southeast-2",
		Profile:       "prod-profile",
		ProfileDir:    "/aws/production",
		LoadOptionFns: []func(*config.LoadOptions) error{customOption},
	}

	cfg, err := newAWSConfigWith(loader, input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Verify region
	if cfg.Region != "ap-southeast-2" {
		t.Errorf("expected region ap-southeast-2, got %s", cfg.Region)
	}

	// Verify profile
	if captured.SharedConfigProfile != "prod-profile" {
		t.Errorf("expected profile prod-profile, got %s", captured.SharedConfigProfile)
	}

	// Verify profile dir
	if len(captured.SharedConfigFiles) != 1 || captured.SharedConfigFiles[0] != "/aws/production/config" {
		t.Errorf("expected SharedConfigFiles [/aws/production/config], got %v", captured.SharedConfigFiles)
	}

	if len(captured.SharedCredentialsFiles) != 1 || captured.SharedCredentialsFiles[0] != "/aws/production/credentials" {
		t.Errorf("expected SharedCredentialsFiles [/aws/production/credentials], got %v", captured.SharedCredentialsFiles)
	}

	// Verify custom option
	if !customOptionCalled {
		t.Error("expected custom LoadOptionFn to be called")
	}
}

// TestResolveRegion_EmptyReturnsDefault verifies default region
func TestResolveRegion_EmptyReturnsDefault(t *testing.T) {
	result := resolveRegion("")
	if result != "us-east-1" {
		t.Errorf("expected us-east-1, got %s", result)
	}
}

// TestResolveRegion_NonEmptyReturnsInput verifies explicit region is returned
func TestResolveRegion_NonEmptyReturnsInput(t *testing.T) {
	result := resolveRegion("eu-central-1")
	if result != "eu-central-1" {
		t.Errorf("expected eu-central-1, got %s", result)
	}
}

// TestBuildLoadOptions_RegionSet verifies region is always included
func TestBuildLoadOptions_RegionSet(t *testing.T) {
	options := buildLoadOptions("us-west-1", "", "")

	// Apply options to LoadOptions to inspect
	opts := config.LoadOptions{}
	for _, fn := range options {
		if err := fn(&opts); err != nil {
			t.Fatalf("option function failed: %v", err)
		}
	}

	if opts.Region != "us-west-1" {
		t.Errorf("expected region us-west-1, got %s", opts.Region)
	}
}

// TestBuildLoadOptions_ProfileSet verifies profile is included when set
func TestBuildLoadOptions_ProfileSet(t *testing.T) {
	options := buildLoadOptions("us-west-1", "test-profile", "")

	opts := config.LoadOptions{}
	for _, fn := range options {
		if err := fn(&opts); err != nil {
			t.Fatalf("option function failed: %v", err)
		}
	}

	if opts.SharedConfigProfile != "test-profile" {
		t.Errorf("expected profile test-profile, got %s", opts.SharedConfigProfile)
	}
}

// TestBuildLoadOptions_ProfileEmpty verifies profile is not included when empty
func TestBuildLoadOptions_ProfileEmpty(t *testing.T) {
	options := buildLoadOptions("us-west-1", "", "")

	opts := config.LoadOptions{}
	for _, fn := range options {
		if err := fn(&opts); err != nil {
			t.Fatalf("option function failed: %v", err)
		}
	}

	if opts.SharedConfigProfile != "" {
		t.Errorf("expected no profile, got %s", opts.SharedConfigProfile)
	}
}

// TestBuildLoadOptions_ProfileDirSet verifies shared config/creds files
func TestBuildLoadOptions_ProfileDirSet(t *testing.T) {
	options := buildLoadOptions("us-west-1", "", "/test/path")

	opts := config.LoadOptions{}
	for _, fn := range options {
		if err := fn(&opts); err != nil {
			t.Fatalf("option function failed: %v", err)
		}
	}

	expectedConfig := "/test/path/config"
	if len(opts.SharedConfigFiles) != 1 || opts.SharedConfigFiles[0] != expectedConfig {
		t.Errorf("expected SharedConfigFiles [%s], got %v", expectedConfig, opts.SharedConfigFiles)
	}

	expectedCreds := "/test/path/credentials"
	if len(opts.SharedCredentialsFiles) != 1 || opts.SharedCredentialsFiles[0] != expectedCreds {
		t.Errorf("expected SharedCredentialsFiles [%s], got %v", expectedCreds, opts.SharedCredentialsFiles)
	}
}

// TestBuildLoadOptions_ProfileDirEmpty verifies no shared files when empty
func TestBuildLoadOptions_ProfileDirEmpty(t *testing.T) {
	options := buildLoadOptions("us-west-1", "", "")

	opts := config.LoadOptions{}
	for _, fn := range options {
		if err := fn(&opts); err != nil {
			t.Fatalf("option function failed: %v", err)
		}
	}

	if len(opts.SharedConfigFiles) > 0 {
		t.Errorf("expected no SharedConfigFiles, got %v", opts.SharedConfigFiles)
	}

	if len(opts.SharedCredentialsFiles) > 0 {
		t.Errorf("expected no SharedCredentialsFiles, got %v", opts.SharedCredentialsFiles)
	}
}

// GetAccountId Tests

// mockSTSClient is a test double for STS GetCallerIdentity calls
type mockSTSClient struct {
	output *sts.GetCallerIdentityOutput
	err    error
}

func (m *mockSTSClient) GetCallerIdentity(ctx context.Context, params *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return m.output, m.err
}

// TestGetAccountId_Success verifies successful account ID retrieval
func TestGetAccountId_Success(t *testing.T) {
	accountID := "123456789012"
	mock := &mockSTSClient{
		output: &sts.GetCallerIdentityOutput{
			Account: &accountID,
		},
		err: nil,
	}

	result, err := getAccountIdWith(mock)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result != accountID {
		t.Errorf("expected account ID %s, got %s", accountID, result)
	}
}

// TestGetAccountId_STSError verifies STS error propagation
func TestGetAccountId_STSError(t *testing.T) {
	expectedErr := errors.New("STS call failed")
	mock := &mockSTSClient{
		output: nil,
		err:    expectedErr,
	}

	_, err := getAccountIdWith(mock)

	if err == nil {
		t.Fatal("expected error from STS, got nil")
	}

	if err.Error() != "failed to get caller identity: STS call failed" {
		t.Errorf("expected error 'failed to get caller identity: STS call failed', got %v", err)
	}
}

// TestGetAccountId_NilAccount verifies nil Account field handling
func TestGetAccountId_NilAccount(t *testing.T) {
	mock := &mockSTSClient{
		output: &sts.GetCallerIdentityOutput{
			Account: nil, // Nil account field
		},
		err: nil,
	}

	_, err := getAccountIdWith(mock)

	if err == nil {
		t.Fatal("expected error for nil Account field, got nil")
	}

	if err.Error() != "account ID not found in caller identity" {
		t.Errorf("expected error 'account ID not found in caller identity', got %v", err)
	}
}
