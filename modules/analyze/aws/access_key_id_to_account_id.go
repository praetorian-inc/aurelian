package analyze

import (
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	op "github.com/praetorian-inc/nebula/internal/output_providers"
	"github.com/praetorian-inc/nebula/modules"
	o "github.com/praetorian-inc/nebula/modules/options"
)

type AwsAccessKeyIdToAccountId struct {
	modules.BaseModule
}

var AwsAccessKeyIdToAccountIdRequiredOptions = []*o.Option{
	&o.AwsAccessKeyIdOpt,
}

var AwsAccessKeyIdToAccountIdOutputProviders = []func(options []*o.Option) modules.OutputProvider{
	op.NewConsoleProvider,
}

var AccessKeyIdToAccountIdMetadata = modules.Metadata{
	Id:          "access-key-id-to-account-id",
	Name:        "Access Key ID to Account ID",
	Description: "This module takes an AWS access key ID and returns the account ID associated with it.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Stealth,
	References: []string{
		"https://awsteele.com/blog/2020/09/26/aws-access-key-format.html",
		"https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489",
	},
}

func NewAccessKeyIdToAccountId(options []*o.Option, run modules.Run) (modules.Module, error) {
	var m AwsAccessKeyIdToAccountId
	m.SetMetdata(AccessKeyIdToAccountIdMetadata)
	m.Run = run
	m.Options = options
	m.ConfigureOutputProviders(AwsAccessKeyIdToAccountIdOutputProviders)

	return &m, nil
}

func (m *AwsAccessKeyIdToAccountId) Invoke() error {

	opt := m.GetOptionByName(o.AwsAccessKeyIdOpt.Name)

	if opt.Value == "" {
		return fmt.Errorf("access_key_id option must be supplied")
	}

	if !m.ValidateAccessKeyID(opt.Value) {
		return fmt.Errorf("access_key_id is not a valid AWS access key ID")
	}

	accessKeyID := opt.Value
	accountID := m.convert(accessKeyID)
	//log.Default().Printf("Access Key ID %s belongs to AWS account %d", accessKeyID, accountID)
	m.Run.Data <- m.MakeResult(accountID)
	close(m.Run.Data)

	return nil
}

func (m *AwsAccessKeyIdToAccountId) convert(AWSKeyID string) int {
	trimmedAWSKeyID := AWSKeyID[4:]                          // remove KeyID prefix
	x, _ := base32.StdEncoding.DecodeString(trimmedAWSKeyID) // base32 decode
	y := make([]byte, 8)
	copy(y[2:], x[0:6])

	z := binary.BigEndian.Uint64(y)
	//z := int(binary.BigEndian.Uint64(y))
	m1, err := hex.DecodeString("7fffffffff80")
	if err != nil {
		fmt.Println(err)
	}
	mask := make([]byte, 8)
	copy(mask[2:], m1)

	e := (z & binary.BigEndian.Uint64(mask)) >> 7
	return int(e)
}

func (m *AwsAccessKeyIdToAccountId) ValidateAccessKeyID(accessKeyID string) bool {
	return len(accessKeyID) == 20
}
