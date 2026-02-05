package aws

import (
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

type AccessKeyToAccountID struct{}

func init() {
	plugin.Register(&AccessKeyToAccountID{})
}

func (m *AccessKeyToAccountID) ID() string {
	return "access-key-to-account-id"
}

func (m *AccessKeyToAccountID) Name() string {
	return "Extract AWS Account ID from AWS Access Key ID"
}

func (m *AccessKeyToAccountID) Description() string {
	return "Extracts AWS Account ID from AWS Access Key ID using base32 decoding"
}

func (m *AccessKeyToAccountID) Platform() plugin.Platform {
	return plugin.PlatformAWS
}

func (m *AccessKeyToAccountID) Category() plugin.Category {
	return plugin.CategoryRecon
}

func (m *AccessKeyToAccountID) OpsecLevel() string {
	return "low"
}

func (m *AccessKeyToAccountID) Authors() []string {
	return []string{"Praetorian"}
}

func (m *AccessKeyToAccountID) References() []string {
	return []string{}
}

func (m *AccessKeyToAccountID) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		plugin.NewParam[string]("access-key-id", "AWS Access Key ID to extract account ID from"),
	}
}

func (m *AccessKeyToAccountID) Run(cfg plugin.Config) ([]plugin.Result, error) {
	accessKeyID, _ := cfg.Args["access-key-id"].(string)
	if accessKeyID == "" {
		return nil, errors.New("access-key-id parameter is required")
	}

	accountID, err := m.processKey(accessKeyID)
	if err != nil {
		return nil, err
	}

	return []plugin.Result{
		{
			Data: map[string]any{
				"access_key_id": accessKeyID,
				"account_id":    accountID,
			},
		},
	}, nil
}

func (m *AccessKeyToAccountID) processKey(awsKeyID string) (string, error) {
	// Skip if key doesn't start with AKIA or ASIA
	if !strings.HasPrefix(awsKeyID, "AKIA") && !strings.HasPrefix(awsKeyID, "ASIA") {
		return "", errors.New("key doesn't have expected AKIA or ASIA prefix")
	}

	trimmedAWSKeyID := awsKeyID[4:] // remove AKIA/ASIA prefix

	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(trimmedAWSKeyID)
	if err != nil {
		return "", fmt.Errorf("failed to decode AWS key ID: %w", err)
	}

	// Create buffer and copy decoded bytes
	buffer := make([]byte, 8)
	copy(buffer[2:], decoded[0:6])

	// Extract account ID using bitmask
	value := binary.BigEndian.Uint64(buffer)
	mask := uint64(0x7fffffffff80)
	accountID := (value & mask) >> 7

	return fmt.Sprintf("%d", accountID), nil
}
