package aws

import (
	"encoding/json"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/utils"
	"gopkg.in/yaml.v3"
)

type KnownAccountID struct {
	*chain.Base
}

type cloudmapperAccount struct {
	Name     string   `yaml:"name"`
	Source   any      `yaml:"source"`
	Accounts []string `yaml:"accounts"`
}

type fwdcloudsecAccount struct {
	Name     string   `yaml:"name"`
	Source   []string `yaml:"source"`
	Accounts []string `yaml:"accounts"`
}

type AwsKnownAccount struct {
	ID          string `json:"id"`
	Owner       string `json:"owner"`
	Source      any    `json:"source"`
	Description string `json:"description"`
}

func NewKnownAccountID(configs ...cfg.Config) chain.Link {
	l := &KnownAccountID{}
	l.Base = chain.NewBase(l, configs...)
	l.Base.SetName("Looks up AWS account IDs against known public accounts")
	return l
}

func (l *KnownAccountID) Process(id string) error {

	l.Logger.Info("Getting known AWS account IDs")

	// Get accounts from rupertbg's repository
	body, err := utils.Cached_httpGet("https://raw.githubusercontent.com/rupertbg/aws-public-account-ids/master/accounts.json")
	if err != nil {
		l.Logger.Error("Error getting known AWS account IDs", "error", err)
		return err
	}

	var accounts []AwsKnownAccount
	err = json.Unmarshal(body, &accounts)
	if err != nil {
		l.Logger.Error("Error unmarshalling known AWS account IDs", "error", err)
		return err
	}

	// Get accounts from fwdcloudsec
	body, err = utils.Cached_httpGet("https://raw.githubusercontent.com/fwdcloudsec/known_aws_accounts/main/accounts.yaml")
	if err != nil {
		l.Logger.Error("Error getting known AWS account IDs", "error", err)
		return err
	}

	fcsAccounts := []fwdcloudsecAccount{}
	err = yaml.Unmarshal(body, &fcsAccounts)
	if err != nil {
		l.Logger.Error("Error unmarshalling fwdcloudsec known AWS account IDs", "error", err)
		return err
	}

	// Get accounts from cloudmapper
	body, err = utils.Cached_httpGet("https://raw.githubusercontent.com/duo-labs/cloudmapper/refs/heads/main/vendor_accounts.yaml")
	if err != nil {
		l.Logger.Error("Error getting known AWS account IDs", "error", err)
		return err
	}

	cmAccounts := []cloudmapperAccount{}
	err = yaml.Unmarshal(body, &cmAccounts)
	if err != nil {
		l.Logger.Error("Error unmarshalling cloudmapper known AWS account IDs", "error", err)
		return err
	}

	for _, account := range cmAccounts {
		for _, accountID := range account.Accounts {
			accounts = append(accounts, AwsKnownAccount{
				ID:     accountID,
				Owner:  account.Name,
				Source: account.Source,
			})
		}
	}

	// Add canary token accounts
	canaryTokens := []string{
		"052310077262", "171436882533", "534261010715",
		"595918472158", "717712589309", "819147034852",
		"992382622183", "730335385048", "266735846894",
	}

	for _, canaryID := range canaryTokens {
		accounts = append(accounts, AwsKnownAccount{
			ID:          canaryID,
			Owner:       "Thinkst",
			Description: "Canary Tokens AWS account",
		})
	}

	// Look for matches
	for _, account := range accounts {
		if account.ID == id {
			return l.Send(account)
		}
	}

	return nil
}
