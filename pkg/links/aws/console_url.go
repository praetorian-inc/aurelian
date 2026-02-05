package aws

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
	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
)

// Constants
const (
	awsFedEndpoint = "https://signin.aws.amazon.com/federation"
	consoleBase    = "https://console.aws.amazon.com/"
	defaultIssuer  = "aws-console-tool"
	minDuration    = 900
	maxDuration    = 129600
)

// Policy represents the IAM policy for federation token
var policy = map[string]interface{}{
	"Version": "2012-10-17",
	"Statement": []map[string]interface{}{
		{
			"Effect":   "Allow",
			"Action":   []string{"*"},
			"Resource": []string{"*"},
		},
	},
}

type AWSConsoleURLLink struct {
	*base.NativeAWSLink
}

func NewAWSConsoleURLLink(args map[string]any) *AWSConsoleURLLink {
	return &AWSConsoleURLLink{
		NativeAWSLink: base.NewNativeAWSLink("aws-console-url", args),
	}
}

func (l *AWSConsoleURLLink) Process(ctx context.Context, input any) ([]any, error) {
	// This link generates console URLs based on configuration, not input
	// Input is ignored as this is typically used as a generator link

	roleArn := l.ArgString("role-arn", "")
	duration := l.ArgInt("duration", 3600)
	mfaToken := l.ArgString("mfa-token", "")
	roleSessionName := l.ArgString("role-session-name", "default-session")
	federationName := l.ArgString("federation-name", "federation-session")

	// Validate duration
	if duration < minDuration || duration > maxDuration {
		return nil, fmt.Errorf("duration must be between %d and %d seconds", minDuration, maxDuration)
	}

	// Get AWS config using base link method
	cfg, err := l.GetConfig(ctx, "us-east-1")
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS config: %w", err)
	}

	// Create STS client
	stsClient := sts.NewFromConfig(cfg)

	// Get temporary credentials
	var credentials *ststypes.Credentials

	// Check if we're already using temporary credentials
	identity, err := l.getCallerIdentity(ctx, stsClient)
	if err != nil {
		return nil, fmt.Errorf("failed to get caller identity: %w", err)
	}

	// If the identity ARN contains "assumed-role", we're already using temporary credentials
	isFederation := false
	if strings.Contains(*identity.Arn, ":assumed-role/") {
		// Extract the temporary credentials from the current config
		creds, err := cfg.Credentials.Retrieve(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve credentials: %w", err)
		}
		credentials = &ststypes.Credentials{
			AccessKeyId:     aws.String(creds.AccessKeyID),
			SecretAccessKey: aws.String(creds.SecretAccessKey),
			SessionToken:    aws.String(creds.SessionToken),
			Expiration:      aws.Time(time.Now().Add(time.Duration(duration) * time.Second)),
		}
	} else if roleArn != "" {
		// Assume role
		credentials, err = l.assumeRole(ctx, stsClient, roleArn, roleSessionName, duration, mfaToken, identity)
		if err != nil {
			return nil, fmt.Errorf("failed to assume role: %w", err)
		}
	} else {
		isFederation = true
		// Get federation token
		credentials, err = l.getFederationToken(ctx, stsClient, federationName, duration)
		if err != nil {
			return nil, fmt.Errorf("failed to get federation token: %w", err)
		}
	}

	// Generate console URL
	consoleURL, err := l.generateConsoleURL(credentials, isFederation, duration)
	if err != nil {
		return nil, fmt.Errorf("failed to generate console URL: %w", err)
	}

	l.Send(consoleURL)
	return l.Outputs(), nil
}

func (l *AWSConsoleURLLink) getCallerIdentity(ctx context.Context, stsClient *sts.Client) (*sts.GetCallerIdentityOutput, error) {
	return stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
}

func (l *AWSConsoleURLLink) assumeRole(ctx context.Context, stsClient *sts.Client, roleArn, roleSessionName string, duration int, mfaToken string, identity *sts.GetCallerIdentityOutput) (*ststypes.Credentials, error) {
	assumeRoleConfig := &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),
		RoleSessionName: aws.String(roleSessionName),
		DurationSeconds: aws.Int32(int32(duration)),
	}

	// Add MFA if token is provided
	if mfaToken != "" {
		// Extract account ID from ARN
		arnParts := strings.Split(*identity.Arn, ":")
		if len(arnParts) < 6 {
			return nil, fmt.Errorf("invalid ARN format: %s", *identity.Arn)
		}
		accountId := arnParts[4]
		userName := strings.Split(arnParts[5], "/")[1]

		// Construct MFA device ARN
		mfaDeviceArn := fmt.Sprintf("arn:aws:iam::%s:mfa/%s", accountId, userName)

		assumeRoleConfig.SerialNumber = aws.String(mfaDeviceArn)
		assumeRoleConfig.TokenCode = aws.String(mfaToken)
	}

	result, err := stsClient.AssumeRole(ctx, assumeRoleConfig)
	if err != nil {
		return nil, err
	}
	return result.Credentials, nil
}

func (l *AWSConsoleURLLink) getFederationToken(ctx context.Context, stsClient *sts.Client, federationName string, duration int) (*ststypes.Credentials, error) {
	policyBytes, err := json.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy: %w", err)
	}

	result, err := stsClient.GetFederationToken(ctx, &sts.GetFederationTokenInput{
		Name:            aws.String(federationName),
		Policy:          aws.String(string(policyBytes)),
		DurationSeconds: aws.Int32(int32(duration)),
	})
	if err != nil {
		return nil, err
	}
	return result.Credentials, nil
}

func (l *AWSConsoleURLLink) generateConsoleURL(credentials *ststypes.Credentials, isFederation bool, duration int) (string, error) {
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
			duration,
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
