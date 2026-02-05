package analyze

import (
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AccessKeyToAccountIDModule{})
}

// AccessKeyToAccountIDModule extracts AWS Account ID from AWS Access Key ID
type AccessKeyToAccountIDModule struct{}

func (m *AccessKeyToAccountIDModule) ID() string {
	return "access-key-to-account-id"
}

func (m *AccessKeyToAccountIDModule) Name() string {
	return "AWS Access Key to Account ID"
}

func (m *AccessKeyToAccountIDModule) Description() string {
	return "Extract AWS Account ID from AWS Access Key ID using base32 decoding."
}

func (m *AccessKeyToAccountIDModule) Platform() plugin.Platform {
	return plugin.PlatformAWS
}

func (m *AccessKeyToAccountIDModule) Category() plugin.Category {
	return plugin.CategoryAnalyze
}

func (m *AccessKeyToAccountIDModule) OpsecLevel() string {
	return "safe"
}

func (m *AccessKeyToAccountIDModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *AccessKeyToAccountIDModule) References() []string {
	return []string{
		"https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489",
	}
}

func (m *AccessKeyToAccountIDModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "access-key-id",
			Description: "AWS Access Key ID (starts with AKIA or ASIA)",
			Type:        "string",
			Required:    true,
		},
	}
}

func (m *AccessKeyToAccountIDModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Get access key ID parameter
	accessKeyID, ok := cfg.Args["access-key-id"].(string)
	if !ok || accessKeyID == "" {
		return nil, fmt.Errorf("access-key-id parameter is required")
	}

	// Validate format
	if !strings.HasPrefix(accessKeyID, "AKIA") && !strings.HasPrefix(accessKeyID, "ASIA") {
		return nil, fmt.Errorf("invalid access key ID format: must start with AKIA or ASIA")
	}

	// Extract account ID
	accountID, err := extractAccountID(accessKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to extract account ID: %w", err)
	}

	// Build result
	data := map[string]any{
		"status":         "success",
		"access_key_id":  accessKeyID,
		"account_id":     accountID,
	}

	return []plugin.Result{
		{
			Data: data,
			Metadata: map[string]any{
				"module":      "access-key-to-account-id",
				"platform":    "aws",
				"opsec_level": "safe",
			},
		},
	}, nil
}

// extractAccountID performs base32 decoding to extract account ID from access key ID
func extractAccountID(accessKeyID string) (string, error) {
	// Remove prefix (AKIA or ASIA)
	var encoded string
	if strings.HasPrefix(accessKeyID, "AKIA") {
		encoded = accessKeyID[4:]
	} else if strings.HasPrefix(accessKeyID, "ASIA") {
		encoded = accessKeyID[4:]
	} else {
		return "", fmt.Errorf("invalid prefix")
	}

	// The account ID is encoded in the first 6 characters after the prefix
	// Decode base32
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encoded[:6])
	if err != nil {
		return "", fmt.Errorf("base32 decode failed: %w", err)
	}

	// Convert to account ID (12-digit number)
	// The decoded bytes contain the account ID in big-endian format
	if len(decoded) < 4 {
		return "", fmt.Errorf("decoded data too short")
	}

	// Extract 12-digit account ID from decoded bytes
	accountID := uint64(decoded[0])<<24 | uint64(decoded[1])<<16 | uint64(decoded[2])<<8 | uint64(decoded[3])

	// Format as 12-digit string with leading zeros
	return fmt.Sprintf("%012d", accountID), nil
}
