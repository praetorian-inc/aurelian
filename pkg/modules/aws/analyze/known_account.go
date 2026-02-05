package analyze

import (
	"encoding/json"
	"fmt"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/utils"
	"gopkg.in/yaml.v3"
)

func init() {
	plugin.Register(&AWSKnownAccountIDModule{})
}

// cloudmapperAccount represents an account from the cloudmapper repository
type cloudmapperAccount struct {
	Name     string   `yaml:"name"`
	Source   any      `yaml:"source"`
	Accounts []string `yaml:"accounts"`
}

// fwdcloudsecAccount represents an account from the fwdcloudsec repository
type fwdcloudsecAccount struct {
	Name     string   `yaml:"name"`
	Source   []string `yaml:"source"`
	Accounts []string `yaml:"accounts"`
}

// AwsKnownAccount represents a known AWS account with metadata
type AwsKnownAccount struct {
	ID          string `json:"id"`
	Owner       string `json:"owner"`
	Source      any    `json:"source"`
	Description string `json:"description"`
}

// AWSKnownAccountIDModule looks up AWS account IDs against known public accounts
type AWSKnownAccountIDModule struct{}

func (m *AWSKnownAccountIDModule) ID() string {
	return "known-account-id"
}

func (m *AWSKnownAccountIDModule) Name() string {
	return "AWS Known Account ID"
}

func (m *AWSKnownAccountIDModule) Description() string {
	return "Looks up AWS account IDs against known public accounts including AWS-owned accounts and canary tokens"
}

func (m *AWSKnownAccountIDModule) Platform() plugin.Platform {
	return plugin.PlatformAWS
}

func (m *AWSKnownAccountIDModule) Category() plugin.Category {
	return plugin.CategoryAnalyze
}

func (m *AWSKnownAccountIDModule) OpsecLevel() string {
	return "safe"
}

func (m *AWSKnownAccountIDModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *AWSKnownAccountIDModule) References() []string {
	return []string{
		"https://github.com/rupertbg/aws-public-account-ids/tree/master",
		"https://github.com/fwdcloudsec/known_aws_accounts",
		"https://github.com/trufflesecurity/trufflehog/blob/4cd055fe3f13b5e17fcb19553c623f1f2720e9f3/pkg/detectors/aws/access_keys/canary.go#L16",
	}
}

func (m *AWSKnownAccountIDModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "account-id",
			Description: "AWS account ID to check",
			Type:        "string",
			Required:    true,
		},
	}
}

func (m *AWSKnownAccountIDModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Get account ID parameter
	accountID, ok := cfg.Args["account-id"].(string)
	if !ok || accountID == "" {
		return nil, fmt.Errorf("account-id parameter is required")
	}

	// Get accounts from rupertbg's repository
	body, err := utils.Cached_httpGet("https://raw.githubusercontent.com/rupertbg/aws-public-account-ids/master/accounts.json")
	if err != nil {
		return nil, fmt.Errorf("error getting known AWS account IDs from rupertbg: %w", err)
	}

	var accounts []AwsKnownAccount
	err = json.Unmarshal(body, &accounts)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling known AWS account IDs from rupertbg: %w", err)
	}

	// Get accounts from fwdcloudsec
	body, err = utils.Cached_httpGet("https://raw.githubusercontent.com/fwdcloudsec/known_aws_accounts/main/accounts.yaml")
	if err != nil {
		return nil, fmt.Errorf("error getting known AWS account IDs from fwdcloudsec: %w", err)
	}

	fcsAccounts := []fwdcloudsecAccount{}
	err = yaml.Unmarshal(body, &fcsAccounts)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling fwdcloudsec known AWS account IDs: %w", err)
	}

	for _, fcsAccount := range fcsAccounts {
		for _, accID := range fcsAccount.Accounts {
			accounts = append(accounts, AwsKnownAccount{
				ID:     accID,
				Owner:  fcsAccount.Name,
				Source: fcsAccount.Source,
			})
		}
	}

	// Get accounts from cloudmapper
	body, err = utils.Cached_httpGet("https://raw.githubusercontent.com/duo-labs/cloudmapper/refs/heads/main/vendor_accounts.yaml")
	if err != nil {
		return nil, fmt.Errorf("error getting known AWS account IDs from cloudmapper: %w", err)
	}

	cmAccounts := []cloudmapperAccount{}
	err = yaml.Unmarshal(body, &cmAccounts)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling cloudmapper known AWS account IDs: %w", err)
	}

	for _, account := range cmAccounts {
		for _, accID := range account.Accounts {
			accounts = append(accounts, AwsKnownAccount{
				ID:     accID,
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
			Source:      "https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/aws/access_keys/canary.go",
		})
	}

	// Look for matches
	for _, account := range accounts {
		if account.ID == accountID {
			return []plugin.Result{
				{
					Data: account,
					Metadata: map[string]any{
						"module":   "known-account-id",
						"platform": "aws",
						"match":    true,
					},
				},
			}, nil
		}
	}

	// Send a "no match" result
	noMatch := AwsKnownAccount{
		ID:          accountID,
		Owner:       "Unknown",
		Source:      "None",
		Description: "Account ID not found in known public accounts",
	}

	return []plugin.Result{
		{
			Data: noMatch,
			Metadata: map[string]any{
				"module":   "known-account-id",
				"platform": "aws",
				"match":    false,
			},
		},
	}, nil
}
