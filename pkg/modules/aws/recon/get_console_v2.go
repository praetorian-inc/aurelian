package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/praetorian-inc/aurelian/internal/helpers"
	"github.com/praetorian-inc/aurelian/pkg/links/options"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

// Constants
const (
	awsFedEndpoint  = "https://signin.aws.amazon.com/federation"
	consoleBase     = "https://console.aws.amazon.com/"
	defaultIssuer   = "aws-console-tool"
	minDuration     = 900
	maxDuration     = 129600
	defaultDuration = 3600
)

// GetConsoleV2 generates a federated sign-in URL for the AWS Console
// using plain Go patterns instead of janus-framework chains.
type GetConsoleV2 struct {
	Profile         string
	Region          string // Default: "us-east-1"
	RoleArn         string // Optional: role to assume
	Duration        int    // Session duration (900-129600 seconds), default 3600
	MfaToken        string // Optional: MFA token
	RoleSessionName string // Optional: session name for assumed role, default "console-session"
	FederationName  string // Optional: federation user name, default "console-user"
}

// NewGetConsoleV2 creates a new console URL generator with sensible defaults.
func NewGetConsoleV2(profile string) *GetConsoleV2 {
	return &GetConsoleV2{
		Profile:         profile,
		Region:          "us-east-1",
		Duration:        defaultDuration,
		RoleSessionName: "console-session",
		FederationName:  "console-user",
	}
}

// Run generates and returns the console sign-in URL.
func (g *GetConsoleV2) Run(ctx context.Context) (string, error) {
	// 1. Validate duration
	if g.Duration < minDuration || g.Duration > maxDuration {
		return "", fmt.Errorf("duration must be between %d and %d seconds", minDuration, maxDuration)
	}

	// 2. Initialize AWS config
	opts := g.defaultCacheOptions()
	config, err := helpers.GetAWSCfg(g.Region, g.Profile, opts, "moderate")
	if err != nil {
		return "", fmt.Errorf("failed to load AWS config: %w", err)
	}

	// 3. Create STS client
	stsClient := sts.NewFromConfig(config)

	// 4. Get caller identity
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("failed to get caller identity: %w", err)
	}

	// 5. Get credentials based on context
	var credentials *ststypes.Credentials
	isFederation := false

	if strings.Contains(*identity.Arn, ":assumed-role/") {
		// Already using temporary credentials
		creds, err := config.Credentials.Retrieve(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to retrieve credentials: %w", err)
		}
		credentials = &ststypes.Credentials{
			AccessKeyId:     aws.String(creds.AccessKeyID),
			SecretAccessKey: aws.String(creds.SecretAccessKey),
			SessionToken:    aws.String(creds.SessionToken),
			Expiration:      aws.Time(time.Now().Add(time.Duration(g.Duration) * time.Second)),
		}
	} else if g.RoleArn != "" {
		// Assume role
		credentials, err = g.assumeRole(ctx, stsClient, identity)
		if err != nil {
			return "", fmt.Errorf("failed to assume role: %w", err)
		}
	} else {
		// Get federation token
		isFederation = true
		credentials, err = g.getFederationToken(ctx, stsClient)
		if err != nil {
			return "", fmt.Errorf("failed to get federation token: %w", err)
		}
	}

	// 6. Generate console URL
	consoleURL, err := g.generateConsoleURL(credentials, isFederation)
	if err != nil {
		return "", fmt.Errorf("failed to generate console URL: %w", err)
	}

	return consoleURL, nil
}

// defaultCacheOptions returns the default cache options required by GetAWSCfg.
func (g *GetConsoleV2) defaultCacheOptions() []*types.Option {
	return []*types.Option{
		&options.AwsCacheDirOpt,
		&options.AwsCacheExtOpt,
		&options.AwsCacheTTLOpt,
		&options.AwsDisableCacheOpt,
		&options.AwsCacheErrorRespOpt,
		&options.AwsCacheErrorRespTypesOpt,
	}
}

// assumeRole assumes the specified IAM role.
func (g *GetConsoleV2) assumeRole(ctx context.Context, stsClient *sts.Client, identity *sts.GetCallerIdentityOutput) (*ststypes.Credentials, error) {
	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(g.RoleArn),
		RoleSessionName: aws.String(g.RoleSessionName),
		DurationSeconds: aws.Int32(int32(g.Duration)),
	}

	// Add MFA if token is provided
	if g.MfaToken != "" {
		arnParts := strings.Split(*identity.Arn, ":")
		if len(arnParts) < 6 {
			return nil, fmt.Errorf("invalid ARN format: %s", *identity.Arn)
		}
		accountId := arnParts[4]
		userName := strings.Split(arnParts[5], "/")[1]
		mfaDeviceArn := fmt.Sprintf("arn:aws:iam::%s:mfa/%s", accountId, userName)

		input.SerialNumber = aws.String(mfaDeviceArn)
		input.TokenCode = aws.String(g.MfaToken)
	}

	result, err := stsClient.AssumeRole(ctx, input)
	if err != nil {
		return nil, err
	}
	return result.Credentials, nil
}

// getFederationToken gets a federation token for console access.
func (g *GetConsoleV2) getFederationToken(ctx context.Context, stsClient *sts.Client) (*ststypes.Credentials, error) {
	policy := map[string]interface{}{
		"Version": "2012-10-17",
		"Statement": []map[string]interface{}{
			{
				"Effect":   "Allow",
				"Action":   []string{"*"},
				"Resource": []string{"*"},
			},
		},
	}

	policyBytes, err := json.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy: %w", err)
	}

	result, err := stsClient.GetFederationToken(ctx, &sts.GetFederationTokenInput{
		Name:            aws.String(g.FederationName),
		Policy:          aws.String(string(policyBytes)),
		DurationSeconds: aws.Int32(int32(g.Duration)),
	})
	if err != nil {
		return nil, err
	}
	return result.Credentials, nil
}

// generateConsoleURL creates the federated console sign-in URL.
func (g *GetConsoleV2) generateConsoleURL(credentials *ststypes.Credentials, isFederation bool) (string, error) {
	// Construct session data
	sessionData := map[string]string{
		"sessionId":    *credentials.AccessKeyId,
		"sessionKey":   *credentials.SecretAccessKey,
		"sessionToken": *credentials.SessionToken,
	}

	sessionDataBytes, err := json.Marshal(sessionData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal session data: %w", err)
	}

	// Get sign-in token
	var federationURL string
	if isFederation {
		federationURL = fmt.Sprintf("%s?Action=getSigninToken&Session=%s",
			awsFedEndpoint,
			url.QueryEscape(string(sessionDataBytes)))
	} else {
		federationURL = fmt.Sprintf("%s?Action=getSigninToken&SessionDuration=%d&Session=%s",
			awsFedEndpoint,
			g.Duration,
			url.QueryEscape(string(sessionDataBytes)))
	}

	resp, err := http.Get(federationURL)
	if err != nil {
		return "", fmt.Errorf("failed to get sign-in token: %w", err)
	}
	defer resp.Body.Close()

	var tokenResponse struct {
		SigninToken string `json:"SigninToken"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return "", fmt.Errorf("failed to decode sign-in token response: %w", err)
	}

	// Build console URL
	consoleURL := fmt.Sprintf("%s?Action=login&Issuer=%s&Destination=%s&SigninToken=%s",
		awsFedEndpoint,
		defaultIssuer,
		consoleBase,
		url.QueryEscape(tokenResponse.SigninToken))

	return consoleURL, nil
}
