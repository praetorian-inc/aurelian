package aws

import (
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

type AwsAccessKeyToAccountId struct {
	*chain.Base
}

func NewAwsAccessKeyToAccountId(configs ...cfg.Config) chain.Link {
	link := &AwsAccessKeyToAccountId{}
	link.Base = chain.NewBase(link, configs...)
	link.SetDescription("Extract AWS Account ID from AWS Access Key ID")
	return link
}

func (l *AwsAccessKeyToAccountId) Params() []cfg.Param {
	return []cfg.Param{options.AwsAccessKeyId()}
}

func (l *AwsAccessKeyToAccountId) Process(input any) error {
	// Convert input to string
	awsKeyId, ok := input.(string)
	if !ok {
		return fmt.Errorf("expected string input, got %T", input)
	}

	// Skip if key doesn't start with AKIA
	if !strings.HasPrefix(awsKeyId, "AKIA") {
		l.Logger.Debug("skipping non-AKIA key", "key", awsKeyId)
		return nil
	}

	trimmedAWSKeyID := awsKeyId[4:] // remove AKIA prefix
	decoded, err := base32.StdEncoding.DecodeString(trimmedAWSKeyID)
	if err != nil {
		return fmt.Errorf("failed to decode AWS key ID: %w", err)
	}

	// Create buffer and copy decoded bytes
	buffer := make([]byte, 8)
	copy(buffer[2:], decoded[0:6])

	// Extract account ID using bitmask
	value := binary.BigEndian.Uint64(buffer)
	mask := uint64(0x7fffffffff80)
	accountId := (value & mask) >> 7

	// Send the account ID as string
	return l.Send(fmt.Sprintf("%d", accountId))
}
