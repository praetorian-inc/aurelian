package analyze

import (
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
)

func init() {
	plugin.Register(&AccessKeyToAccountIDModule{})
}

type AccessKeyToAccountIDConfig struct {
	AccessKeyID string `param:"access-key-id" desc:"AWS access key ID (AKIA... or ASIA...)" required:"true" shortcode:"k"`
}

type AccessKeyToAccountIDModule struct {
	AccessKeyToAccountIDConfig
}

func (m *AccessKeyToAccountIDModule) ID() string                { return "access-key-to-account-id" }
func (m *AccessKeyToAccountIDModule) Name() string              { return "AWS Access Key to Account ID" }
func (m *AccessKeyToAccountIDModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *AccessKeyToAccountIDModule) Category() plugin.Category { return plugin.CategoryAnalyze }
func (m *AccessKeyToAccountIDModule) OpsecLevel() string        { return "safe" }
func (m *AccessKeyToAccountIDModule) Authors() []string         { return []string{"Praetorian"} }

func (m *AccessKeyToAccountIDModule) Description() string {
	return "Derives the AWS account ID from an access key ID using base32 decoding without making any API calls."
}

func (m *AccessKeyToAccountIDModule) References() []string {
	return []string{
		"https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489",
		"https://hackingthe.cloud/aws/enumeration/account-id-from-access-key/",
	}
}

func (m *AccessKeyToAccountIDModule) SupportedResourceTypes() []string { return nil }

func (m *AccessKeyToAccountIDModule) Parameters() any {
	return &m.AccessKeyToAccountIDConfig
}

func (m *AccessKeyToAccountIDModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	key := strings.TrimSpace(m.AccessKeyID)

	if !strings.HasPrefix(key, "AKIA") && !strings.HasPrefix(key, "ASIA") {
		return fmt.Errorf("invalid access key prefix: must start with AKIA or ASIA, got %q", key[:min(4, len(key))])
	}

	accountID, err := accountIDFromAccessKey(key)
	if err != nil {
		return fmt.Errorf("decoding access key: %w", err)
	}

	cfg.Success("access key %s belongs to account %s", key, accountID)

	return nil
}

// accountIDFromAccessKey extracts the AWS account ID encoded in an access key ID.
// The key ID (after the 4-char prefix) is base32-encoded. The account ID is
// embedded in bits 7–46 of the first 6 decoded bytes.
func accountIDFromAccessKey(keyID string) (string, error) {
	trimmed := keyID[4:]

	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(trimmed)
	if err != nil {
		return "", fmt.Errorf("base32 decode: %w", err)
	}

	if len(decoded) < 6 {
		return "", fmt.Errorf("decoded key too short: %d bytes", len(decoded))
	}

	// Pack the first 6 decoded bytes into a uint64 (big-endian, right-aligned).
	var buf [8]byte
	copy(buf[2:], decoded[:6])
	val := binary.BigEndian.Uint64(buf[:])

	// The account ID occupies bits 7–46 (mask then shift right by 7 to get a 40-bit value).
	accountID := (val & 0x7fffffffff80) >> 7

	return fmt.Sprintf("%012d", accountID), nil
}
