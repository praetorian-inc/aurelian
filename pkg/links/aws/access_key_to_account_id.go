package aws

import (
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/links/options"
)

type AwsAccessKeyToAccountId struct {
	*chain.Base
}

func NewAwsAccessKeyToAccountId(configs ...cfg.Config) chain.Link {
	link := &AwsAccessKeyToAccountId{}
	link.Base = chain.NewBase(link, configs...)
	link.Base.SetName("Extract AWS Account ID from AWS Access Key ID")
	return link
}

func (l *AwsAccessKeyToAccountId) Params() []cfg.Param {
	return []cfg.Param{options.AwsAccessKeyId()}
}

func (l *AwsAccessKeyToAccountId) Initialize() error {
	// Get the access key from params if available
	accessKeyId, err := cfg.As[string](l.Arg("access-key-id"))
	if err == nil && accessKeyId != "" {
		l.Logger.Info("Got access key ID from parameters", "key", accessKeyId)
		// Process the key if provided as parameter
		return l.processKey(accessKeyId)
	}
	return nil
}

func (l *AwsAccessKeyToAccountId) Process(input any) error {
	// Convert input to string
	l.Logger.Info("Processing input", "input", input)

	awsKeyId, ok := input.(string)
	if !ok {
		errMsg := fmt.Sprintf("expected string input, got %T", input)
		l.Logger.Error(errMsg)
		return fmt.Errorf(errMsg)
	}

	return l.processKey(awsKeyId)
}

func (l *AwsAccessKeyToAccountId) processKey(awsKeyId string) error {
	l.Logger.Info("Processing AWS access key", "key", awsKeyId)

	// Skip if key doesn't start with AKIA or ASIA
	if !strings.HasPrefix(awsKeyId, "AKIA") && !strings.HasPrefix(awsKeyId, "ASIA") {
		l.Logger.Debug("skipping non-AKI/ASI key", "key", awsKeyId)
		l.Logger.Info("Key doesn't have expected prefix", "key", awsKeyId)
		return nil
	}

	trimmedAWSKeyID := awsKeyId[4:] // remove AKIA/ASIA prefix
	l.Logger.Info("Trimmed key", "trimmed", trimmedAWSKeyID)

	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(trimmedAWSKeyID)
	if err != nil {
		errMsg := fmt.Sprintf("failed to decode AWS key ID: %v", err)
		l.Logger.Error(errMsg)
		return fmt.Errorf(errMsg)
	}
	l.Logger.Info("Decoded bytes", "bytes", fmt.Sprintf("%v", decoded), "length", len(decoded))

	// Create buffer and copy decoded bytes
	buffer := make([]byte, 8)
	copy(buffer[2:], decoded[0:6])
	l.Logger.Info("Buffer after copy", "buffer", fmt.Sprintf("%v", buffer))

	// Extract account ID using bitmask
	value := binary.BigEndian.Uint64(buffer)
	l.Logger.Info("BigEndian value", "value", value)

	mask := uint64(0x7fffffffff80)
	accountId := (value & mask) >> 7
	l.Logger.Info("Calculated account ID", "account_id", accountId)

	// Send the account ID as string
	accountIdStr := fmt.Sprintf("%d", accountId)
	l.Logger.Info("Sending account ID", "account_id_str", accountIdStr)

	return l.Send(accountIdStr)
}
