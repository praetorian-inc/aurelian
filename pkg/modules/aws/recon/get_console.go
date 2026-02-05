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
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/types"
)

func init() {
	plugin.Register(&GetConsoleModule{})
}

// Constants for federation
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

type GetConsoleModule struct{}

func (m *GetConsoleModule) ID() string {
	return "get-console"
}

func (m *GetConsoleModule) Name() string {
	return "AWS Get Console URL"
}

func (m *GetConsoleModule) Description() string {
	return "Generate a federated sign-in URL for the AWS Console using temporary credentials"
}

func (m *GetConsoleModule) Platform() plugin.Platform {
	return plugin.PlatformAWS
}

func (m *GetConsoleModule) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *GetConsoleModule) OpsecLevel() string {
	return "moderate"
}

func (m *GetConsoleModule) Authors() []string {
	return []string{"Bernard Yip", "Praetorian"}
}

func (m *GetConsoleModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_enable-regions.html",
		"https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-signing.html",
	}
}

func (m *GetConsoleModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "profile",
			Description: "AWS profile name",
			Type:        "string",
		},
		{
			Name:        "profile-dir",
			Description: "AWS profile directory",
			Type:        "string",
		},
		{
			Name:        "role-arn",
			Description: "ARN of the IAM role to assume",
			Type:        "string",
		},
		{
			Name:        "duration",
			Description: "Session duration in seconds (900-129600)",
			Type:        "int",
			Default:     43200, // 12 hours
		},
		{
			Name:        "mfa-token",
			Description: "MFA token code if required",
			Type:        "string",
		},
		{
			Name:        "role-session-name",
			Description: "Name for the assumed role session",
			Type:        "string",
			Default:     "console-session",
		},
		{
			Name:        "federation-name",
			Description: "Name for the federation token",
			Type:        "string",
			Default:     "console-user",
		},
	}
}

func (m *GetConsoleModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Extract parameters
	profile, _ := cfg.Args["profile"].(string)
	profileDir, _ := cfg.Args["profile-dir"].(string)
	roleArn, _ := cfg.Args["role-arn"].(string)
	duration := 43200 // default 12 hours
	if d, ok := cfg.Args["duration"].(int); ok {
		duration = d
	}
	mfaToken, _ := cfg.Args["mfa-token"].(string)
	roleSessionName, _ := cfg.Args["role-session-name"].(string)
	if roleSessionName == "" {
		roleSessionName = "console-session"
	}
	federationName, _ := cfg.Args["federation-name"].(string)
	if federationName == "" {
		federationName = "console-user"
	}

	// Validate duration
	if duration < minDuration || duration > maxDuration {
		return nil, fmt.Errorf("duration must be between %d and %d seconds", minDuration, maxDuration)
	}

	// Build opts slice for GetAWSCfg
	var opts []*types.Option
	if profileDir != "" {
		opts = append(opts, &types.Option{
			Name:  "profile-dir",
			Value: profileDir,
		})
	}

	// Get AWS config
	awsCfg, err := helpers.GetAWSCfg("us-east-1", profile, opts, "moderate")
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS config: %w", err)
	}

	// Create STS client
	stsClient := sts.NewFromConfig(awsCfg)

	// Get caller identity to determine credential type
	identity, err := m.getCallerIdentity(cfg.Context, stsClient)
	if err != nil {
		return nil, fmt.Errorf("failed to get caller identity: %w", err)
	}

	// Get temporary credentials
	var credentials *ststypes.Credentials
	isFederation := false

	// Check if already using temporary credentials (assumed-role)
	if strings.Contains(*identity.Arn, ":assumed-role/") {
		// Extract temporary credentials from current config
		creds, err := awsCfg.Credentials.Retrieve(cfg.Context)
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
		credentials, err = m.assumeRole(cfg.Context, stsClient, roleArn, roleSessionName, duration, mfaToken, identity)
		if err != nil {
			return nil, fmt.Errorf("failed to assume role: %w", err)
		}
	} else {
		// Get federation token
		isFederation = true
		credentials, err = m.getFederationToken(cfg.Context, stsClient, federationName, duration)
		if err != nil {
			return nil, fmt.Errorf("failed to get federation token: %w", err)
		}
	}

	// Generate console URL
	consoleURL, err := m.generateConsoleURL(credentials, isFederation, duration)
	if err != nil {
		return nil, fmt.Errorf("failed to generate console URL: %w", err)
	}

	// Build result
	data := map[string]any{
		"status":      "success",
		"console_url": consoleURL,
		"expiration":  credentials.Expiration.Format(time.RFC3339),
		"method":      m.determineMethod(isFederation, roleArn, identity),
	}

	return []plugin.Result{
		{
			Data: data,
			Metadata: map[string]any{
				"module":      "get-console",
				"platform":    "aws",
				"opsec_level": "moderate",
			},
		},
	}, nil
}

func (m *GetConsoleModule) getCallerIdentity(ctx context.Context, stsClient *sts.Client) (*sts.GetCallerIdentityOutput, error) {
	return stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
}

func (m *GetConsoleModule) assumeRole(ctx context.Context, stsClient *sts.Client, roleArn, roleSessionName string, duration int, mfaToken string, identity *sts.GetCallerIdentityOutput) (*ststypes.Credentials, error) {
	assumeRoleInput := &sts.AssumeRoleInput{
		RoleArn:         aws.String(roleArn),
		RoleSessionName: aws.String(roleSessionName),
		DurationSeconds: aws.Int32(int32(duration)),
	}

	// Add MFA if token provided
	if mfaToken != "" {
		// Extract account ID and username from ARN
		arnParts := strings.Split(*identity.Arn, ":")
		if len(arnParts) < 6 {
			return nil, fmt.Errorf("invalid ARN format: %s", *identity.Arn)
		}
		accountId := arnParts[4]
		userName := strings.Split(arnParts[5], "/")[1]

		// Construct MFA device ARN
		mfaDeviceArn := fmt.Sprintf("arn:aws:iam::%s:mfa/%s", accountId, userName)

		assumeRoleInput.SerialNumber = aws.String(mfaDeviceArn)
		assumeRoleInput.TokenCode = aws.String(mfaToken)
	}

	result, err := stsClient.AssumeRole(ctx, assumeRoleInput)
	if err != nil {
		return nil, err
	}
	return result.Credentials, nil
}

func (m *GetConsoleModule) getFederationToken(ctx context.Context, stsClient *sts.Client, federationName string, duration int) (*ststypes.Credentials, error) {
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

func (m *GetConsoleModule) generateConsoleURL(credentials *ststypes.Credentials, isFederation bool, duration int) (string, error) {
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

func (m *GetConsoleModule) determineMethod(isFederation bool, roleArn string, identity *sts.GetCallerIdentityOutput) string {
	if strings.Contains(*identity.Arn, ":assumed-role/") {
		return "existing_temporary_credentials"
	} else if roleArn != "" {
		return "assume_role"
	} else if isFederation {
		return "federation_token"
	}
	return "unknown"
}
