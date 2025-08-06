package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/aws/base"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

// Constants
const (
	awsFedEndpoint = "https://signin.aws.amazon.com/federation"
	consoleBase    = "https://console.aws.amazon.com/"
	defaultIssuer  = "aws-console-tool"
	minDuration    = 900
	maxDuration    = 3600
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
	*base.AwsReconBaseLink
}

func NewAWSConsoleURLLink(configs ...cfg.Config) chain.Link {
	l := &AWSConsoleURLLink{}
	l.AwsReconBaseLink = base.NewAwsReconBaseLink(l, configs...)
	return l
}

func (l *AWSConsoleURLLink) Params() []cfg.Param {
	return append(l.AwsReconBaseLink.Params(),
		options.AwsRoleArn(),
		options.AwsSessionDuration(),
		options.AwsMfaToken(),
		options.AwsRoleSessionName(),
		options.AwsFederationName(),
	)
}

func (l *AWSConsoleURLLink) Process(input any) error {
	// This link generates console URLs based on configuration, not input
	// Input is ignored as this is typically used as a generator link
	
	roleArn, _ := cfg.As[string](l.Arg("role-arn"))
	duration, _ := cfg.As[int](l.Arg("duration"))
	mfaToken, _ := cfg.As[string](l.Arg("mfa-token"))
	roleSessionName, _ := cfg.As[string](l.Arg("role-session-name"))
	federationName, _ := cfg.As[string](l.Arg("federation-name"))

	// Validate duration
	if duration < minDuration || duration > maxDuration {
		return fmt.Errorf("duration must be between %d and %d seconds", minDuration, maxDuration)
	}

	// Get AWS config using base link method
	cfg, err := l.GetConfigWithRuntimeArgs("us-east-1")
	if err != nil {
		return fmt.Errorf("failed to get AWS config: %w", err)
	}

	// Create STS client
	stsClient := sts.NewFromConfig(cfg)

	// Get temporary credentials
	var credentials *ststypes.Credentials

	// Check if we're already using temporary credentials
	identity, err := l.getCallerIdentity(stsClient)
	if err != nil {
		return fmt.Errorf("failed to get caller identity: %w", err)
	}

	// If the identity ARN contains "assumed-role", we're already using temporary credentials
	if strings.Contains(*identity.Arn, ":assumed-role/") {
		// Extract the temporary credentials from the current config
		creds, err := cfg.Credentials.Retrieve(l.Context())
		if err != nil {
			return fmt.Errorf("failed to retrieve credentials: %w", err)
		}
		credentials = &ststypes.Credentials{
			AccessKeyId:     aws.String(creds.AccessKeyID),
			SecretAccessKey: aws.String(creds.SecretAccessKey),
			SessionToken:    aws.String(creds.SessionToken),
			Expiration:      aws.Time(time.Now().Add(time.Duration(duration) * time.Second)),
		}
	} else if roleArn != "" {
		// Assume role
		credentials, err = l.assumeRole(stsClient, roleArn, roleSessionName, duration, mfaToken, identity)
		if err != nil {
			return fmt.Errorf("failed to assume role: %w", err)
		}
	} else {
		// Get federation token
		credentials, err = l.getFederationToken(stsClient, federationName, duration)
		if err != nil {
			return fmt.Errorf("failed to get federation token: %w", err)
		}
	}

	// Generate console URL
	consoleURL, err := l.generateConsoleURL(credentials)
	if err != nil {
		return fmt.Errorf("failed to generate console URL: %w", err)
	}

	l.Send(consoleURL)
	return nil
}

func (l *AWSConsoleURLLink) getCallerIdentity(stsClient *sts.Client) (*sts.GetCallerIdentityOutput, error) {
	return stsClient.GetCallerIdentity(l.Context(), &sts.GetCallerIdentityInput{})
}

func (l *AWSConsoleURLLink) assumeRole(stsClient *sts.Client, roleArn, roleSessionName string, duration int, mfaToken string, identity *sts.GetCallerIdentityOutput) (*ststypes.Credentials, error) {
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

	result, err := stsClient.AssumeRole(l.Context(), assumeRoleConfig)
	if err != nil {
		return nil, err
	}
	return result.Credentials, nil
}

func (l *AWSConsoleURLLink) getFederationToken(stsClient *sts.Client, federationName string, duration int) (*ststypes.Credentials, error) {
	policyBytes, err := json.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal policy: %w", err)
	}

	result, err := stsClient.GetFederationToken(l.Context(), &sts.GetFederationTokenInput{
		Name:            aws.String(federationName),
		Policy:          aws.String(string(policyBytes)),
		DurationSeconds: aws.Int32(int32(duration)),
	})
	if err != nil {
		return nil, err
	}
	return result.Credentials, nil
}

func (l *AWSConsoleURLLink) generateConsoleURL(credentials *ststypes.Credentials) (string, error) {
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
	federationURL := fmt.Sprintf("%s?Action=getSigninToken&Session=%s",
		awsFedEndpoint,
		url.QueryEscape(string(sessionDataBytes)))

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