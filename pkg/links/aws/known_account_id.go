package aws

import (
	"context"
	"encoding/json"

	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/outputters"
	"github.com/praetorian-inc/aurelian/pkg/utils"
	"gopkg.in/yaml.v3"
)

type KnownAccountID struct {
	*base.NativeAWSLink
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

func NewKnownAccountID(args map[string]any) *KnownAccountID {
	return &KnownAccountID{
		NativeAWSLink: base.NewNativeAWSLink("known-account-id", args),
	}
}

func (l *KnownAccountID) Process(ctx context.Context, input any) ([]any, error) {
	id, ok := input.(string)
	if !ok {
		return nil, nil
	}

	// Get accounts from rupertbg's repository
	body, err := utils.Cached_httpGet("https://raw.githubusercontent.com/rupertbg/aws-public-account-ids/master/accounts.json")
	if err != nil {
		return nil, err
	}

	var accounts []AwsKnownAccount
	err = json.Unmarshal(body, &accounts)
	if err != nil {
		return nil, err
	}

	// Get accounts from fwdcloudsec
	body, err = utils.Cached_httpGet("https://raw.githubusercontent.com/fwdcloudsec/known_aws_accounts/main/accounts.yaml")
	if err != nil {
		return nil, err
	}

	fcsAccounts := []fwdcloudsecAccount{}
	err = yaml.Unmarshal(body, &fcsAccounts)
	if err != nil {
		return nil, err
	}

	// Get accounts from cloudmapper
	body, err = utils.Cached_httpGet("https://raw.githubusercontent.com/duo-labs/cloudmapper/refs/heads/main/vendor_accounts.yaml")
	if err != nil {
		return nil, err
	}

	cmAccounts := []cloudmapperAccount{}
	err = yaml.Unmarshal(body, &cmAccounts)
	if err != nil {
		return nil, err
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
			l.Send(outputters.RawOutput{Data: account})
			return l.Outputs(), nil
		}
	}

	// Send a "no match" result
	noMatch := AwsKnownAccount{
		ID:          id,
		Owner:       "Unknown",
		Source:      "None",
		Description: "Account ID not found in known public accounts",
	}
	l.Send(outputters.RawOutput{Data: noMatch})
	return l.Outputs(), nil
}
