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
	awshelpers "github.com/praetorian-inc/aurelian/internal/helpers/aws"
	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

const (
	awsFedEndpoint = "https://signin.aws.amazon.com/federation"
	consoleBase    = "https://console.aws.amazon.com/"
	defaultIssuer  = "aurelian"
	minDuration    = 900
	maxDuration    = 129600
)

// federationPolicy grants Action:* / Resource:* intentionally. GetFederationToken
// returns credentials scoped to the intersection of this policy and the calling
// IAM user's permissions, so the resulting session never exceeds the caller's
// existing privileges. This mirrors Nebula's console_url implementation.
var federationPolicy = map[string]any{
	"Version": "2012-10-17",
	"Statement": []map[string]any{
		{
			"Effect":   "Allow",
			"Action":   []string{"*"},
			"Resource": []string{"*"},
		},
	},
}

func init() {
	plugin.Register(&GetConsoleModule{})
}

// GetConsoleConfig holds the typed parameters for the get-console module.
type GetConsoleConfig struct {
	plugin.AWSReconBase
	RoleARN         string `param:"role-arn"           desc:"IAM role ARN to assume before generating console URL"`
	Duration        int    `param:"duration"           desc:"Session duration in seconds (900-129600)" default:"3600"`
	MFAToken        string `param:"mfa-token"          desc:"MFA token code for role assumption"`
	RoleSessionName string `param:"role-session-name"  desc:"Session name for assumed role" default:"aurelian-console"`
	FederationName  string `param:"federation-name"    desc:"Name for federation token request" default:"aurelian-console"`
}

// GetConsoleModule generates a federated AWS Console sign-in URL using STS credentials.
type GetConsoleModule struct {
	GetConsoleConfig
}

func (m *GetConsoleModule) ID() string                { return "get-console" }
func (m *GetConsoleModule) Name() string              { return "AWS Get Console URL" }
func (m *GetConsoleModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *GetConsoleModule) Category() plugin.Category { return plugin.CategoryRecon }
func (m *GetConsoleModule) OpsecLevel() string        { return "moderate" }
func (m *GetConsoleModule) Authors() []string         { return []string{"Bernard Yip", "Praetorian"} }

func (m *GetConsoleModule) Description() string {
	return "Generates a federated AWS Console sign-in URL using STS credentials. " +
		"Supports three credential paths: existing assumed-role session, role assumption via AssumeRole, " +
		"and federation token via GetFederationToken."
}

func (m *GetConsoleModule) References() []string {
	return []string{
		"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html",
		"https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html",
		"https://docs.aws.amazon.com/STS/latest/APIReference/API_GetFederationToken.html",
	}
}

func (m *GetConsoleModule) SupportedResourceTypes() []string {
	return nil
}

func (m *GetConsoleModule) Parameters() any {
	return &m.GetConsoleConfig
}

// consoleResult holds the structured output for the get-console module.
type consoleResult struct {
	ConsoleURL       string `json:"console_url"`
	IdentityARN      string `json:"identity_arn"`
	CredentialMethod string `json:"credential_method"`
	Expiration       string `json:"expiration"`
}

func (m *GetConsoleModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.GetConsoleConfig

	if c.Duration < minDuration || c.Duration > maxDuration {
		return fmt.Errorf("duration %d is out of range: must be between %d and %d seconds", c.Duration, minDuration, maxDuration)
	}

	awsCfg, err := awshelpers.NewAWSConfig(awshelpers.AWSConfigInput{
		Region:     "us-east-1",
		Profile:    c.Profile,
		ProfileDir: c.ProfileDir,
	})
	if err != nil {
		return fmt.Errorf("loading AWS config: %w", err)
	}

	stsClient := sts.NewFromConfig(awsCfg)

	identity, err := stsClient.GetCallerIdentity(cfg.Context, &sts.GetCallerIdentityInput{})
	if err != nil {
		return fmt.Errorf("getting caller identity: %w", err)
	}

	identityARN := aws.ToString(identity.Arn)
	cfg.Info("current identity: %s", identityARN)

	var (
		accessKeyID     string
		secretAccessKey string
		sessionToken    string
		expiration      time.Time
		credMethod      string
	)

	switch {
	case c.RoleARN != "":
		input := &sts.AssumeRoleInput{
			RoleArn:         aws.String(c.RoleARN),
			RoleSessionName: aws.String(c.RoleSessionName),
			DurationSeconds: aws.Int32(int32(c.Duration)),
		}
		if c.MFAToken != "" {
			mfaSerial, mfaErr := mfaDeviceARN(identityARN)
			if mfaErr != nil {
				return fmt.Errorf("constructing MFA serial: %w", mfaErr)
			}
			input.SerialNumber = aws.String(mfaSerial)
			input.TokenCode = aws.String(c.MFAToken)
		}
		assumed, assumeErr := stsClient.AssumeRole(cfg.Context, input)
		if assumeErr != nil {
			return fmt.Errorf("assuming role %s: %w", c.RoleARN, assumeErr)
		}
		accessKeyID, secretAccessKey, sessionToken, expiration = extractCreds(assumed.Credentials)
		credMethod = "assume-role"

	case strings.Contains(identityARN, ":assumed-role/"):
		// Use existing temp credentials from the loaded AWS config.
		creds, credsErr := awsCfg.Credentials.Retrieve(cfg.Context)
		if credsErr != nil {
			return fmt.Errorf("retrieving credentials: %w", credsErr)
		}
		accessKeyID = creds.AccessKeyID
		secretAccessKey = creds.SecretAccessKey
		sessionToken = creds.SessionToken
		expiration = creds.Expires
		credMethod = "existing-session"

	default:
		policyBytes, policyErr := json.Marshal(federationPolicy)
		if policyErr != nil {
			return fmt.Errorf("marshaling federation policy: %w", policyErr)
		}
		fedInput := &sts.GetFederationTokenInput{
			Name:            aws.String(c.FederationName),
			DurationSeconds: aws.Int32(int32(c.Duration)),
			Policy:          aws.String(string(policyBytes)),
		}
		fedToken, fedErr := stsClient.GetFederationToken(cfg.Context, fedInput)
		if fedErr != nil {
			return fmt.Errorf("getting federation token: %w", fedErr)
		}
		accessKeyID, secretAccessKey, sessionToken, expiration = extractCreds(fedToken.Credentials)
		credMethod = "federation-token"
	}

	consoleURL, err := buildConsoleURL(cfg.Context, awsFedEndpoint, accessKeyID, secretAccessKey, sessionToken, credMethod, c.Duration)
	if err != nil {
		return fmt.Errorf("building console URL: %w", err)
	}

	result := consoleResult{
		ConsoleURL:       consoleURL,
		IdentityARN:      identityARN,
		CredentialMethod: credMethod,
		Expiration:       expiration.UTC().Format(time.RFC3339),
	}

	resultBytes, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshaling result: %w", err)
	}

	out.Send(output.AnalyzeResult{
		Module:  m.ID(),
		Input:   identityARN,
		Results: json.RawMessage(resultBytes),
	})
	return nil
}

// mfaDeviceARN constructs the MFA device ARN from the caller identity ARN.
// It parses the account ID and username from an ARN of the form
// arn:aws:iam::ACCOUNT:user/USERNAME and returns arn:aws:iam::ACCOUNT:mfa/USERNAME.
func mfaDeviceARN(callerARN string) (string, error) {
	// Expected format: arn:aws:iam::ACCOUNT:user/USERNAME
	parts := strings.Split(callerARN, ":")
	if len(parts) < 6 {
		return "", fmt.Errorf("unexpected ARN format: %s", callerARN)
	}
	accountID := parts[4]
	resourcePart := parts[5] // e.g. "user/USERNAME"
	slashIdx := strings.LastIndex(resourcePart, "/")
	if slashIdx < 0 {
		return "", fmt.Errorf("no username found in ARN resource part: %s", resourcePart)
	}
	username := resourcePart[slashIdx+1:]
	return fmt.Sprintf("arn:aws:iam::%s:mfa/%s", accountID, username), nil
}

// extractCreds unpacks an STS credentials struct into its component values.
func extractCreds(creds *ststypes.Credentials) (accessKeyID, secretAccessKey, sessionToken string, expiration time.Time) {
	if creds == nil {
		return
	}
	accessKeyID = aws.ToString(creds.AccessKeyId)
	secretAccessKey = aws.ToString(creds.SecretAccessKey)
	sessionToken = aws.ToString(creds.SessionToken)
	if creds.Expiration != nil {
		expiration = *creds.Expiration
	}
	return
}

// signinTokenResponse is the JSON structure returned by the federation endpoint.
type signinTokenResponse struct {
	SigninToken string `json:"SigninToken"`
}

// buildConsoleURL exchanges temporary credentials for a federation SigninToken
// and returns a ready-to-use AWS console URL. fedEndpoint is the federation
// endpoint base URL (normally awsFedEndpoint; injectable for testing).
func buildConsoleURL(ctx context.Context, fedEndpoint, accessKeyID, secretAccessKey, sessionToken, credMethod string, duration int) (string, error) {
	sessionData, err := json.Marshal(map[string]string{
		"sessionId":    accessKeyID,
		"sessionKey":   secretAccessKey,
		"sessionToken": sessionToken,
	})
	if err != nil {
		return "", fmt.Errorf("marshaling session data: %w", err)
	}

	var fedURL string
	if credMethod == "federation-token" {
		fedURL = fmt.Sprintf("%s?Action=getSigninToken&SessionDuration=%d&Session=%s",
			fedEndpoint,
			duration,
			url.QueryEscape(string(sessionData)),
		)
	} else {
		fedURL = fmt.Sprintf("%s?Action=getSigninToken&Session=%s",
			fedEndpoint,
			url.QueryEscape(string(sessionData)),
		)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fedURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating signin token request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching signin token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("federation endpoint returned status %d", resp.StatusCode)
	}

	var tokenResp signinTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("decoding signin token response: %w", err)
	}
	if tokenResp.SigninToken == "" {
		return "", fmt.Errorf("federation endpoint returned empty signin token")
	}

	consoleURL := fmt.Sprintf("%s?Action=login&Issuer=%s&Destination=%s&SigninToken=%s",
		fedEndpoint,
		url.QueryEscape(defaultIssuer),
		url.QueryEscape(consoleBase),
		url.QueryEscape(tokenResp.SigninToken),
	)

	return consoleURL, nil
}
