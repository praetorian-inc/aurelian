package analyze

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/praetorian-inc/nebula/modules"
	o "github.com/praetorian-inc/nebula/modules/options"
)

type KnownAccountID struct {
	modules.BaseModule
}

var KnownAccountIDRequiredOptions = []*o.Option{
	&o.AwsAccountIdOpt,
}

var KnownAccountIDMetadata = modules.Metadata{
	Id:          "known-account-id",
	Name:        "Known Account ID",
	Description: "This module takes an AWS account ID and returns returns information about it if known.",
	Platform:    modules.AWS,
	Authors:     []string{"Praetorian"},
	OpsecLevel:  modules.Stealth,
	References: []string{
		"https://github.com/rupertbg/aws-public-account-ids/tree/master",
	},
}

func NewKnownAccountID(options []*o.Option, run modules.Run) (modules.Module, error) {
	var m KnownAccountID
	m.SetMetdata(KnownAccountIDMetadata)
	m.Run = run
	m.Options = options

	return &m, nil
}

func (m *KnownAccountID) Invoke() error {
	opt := m.GetOptionByName(o.AwsAccountIdOpt.Name)

	if opt.Value == "" {
		return fmt.Errorf("access_key_id option must be supplied")
	}

	resp, err := http.Get("https://raw.githubusercontent.com/rupertbg/aws-public-account-ids/master/accounts.json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var accounts []Account
	err = json.Unmarshal(body, &accounts)
	if err != nil {
		return err
	}

	for _, account := range accounts {
		if account.ID == opt.Value {
			r := m.MakeResult(account)
			m.Run.Data <- r
			close(m.Run.Data)
			break
		}
	}

	return nil

}

type Account struct {
	ID          string      `json:"id"`
	Owner       string      `json:"owner"`
	Source      interface{} `json:"source"`
	Description string      `json:"description"`
}
