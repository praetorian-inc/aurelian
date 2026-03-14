package analyze

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/praetorian-inc/aurelian/pkg/model"
	"github.com/praetorian-inc/aurelian/pkg/output"
	"github.com/praetorian-inc/aurelian/pkg/pipeline"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"gopkg.in/yaml.v3"
)

const (
	knownAccountsJSONURL  = "https://raw.githubusercontent.com/rupertbg/aws-public-account-ids/master/accounts.json"
	knownAccountsYAML1URL = "https://raw.githubusercontent.com/fwdcloudsec/known_aws_accounts/main/accounts.yaml"
	knownAccountsYAML2URL = "https://raw.githubusercontent.com/duo-labs/cloudmapper/refs/heads/main/vendor_accounts.yaml"
)

// thinkstCanaryAccounts are known Thinkst Canary token AWS account IDs.
var thinkstCanaryAccounts = []string{
	"052310077262",
	"171436882533",
	"534261010715",
	"595918472158",
	"717712589309",
	"819147034852",
	"992382622183",
	"730335385048",
	"266735846894",
}

func init() {
	plugin.Register(&KnownAccountModule{})
}

type KnownAccountConfig struct {
	AccountID string `param:"account-id" desc:"AWS account ID to look up" required:"true"`
}

type KnownAccountModule struct {
	KnownAccountConfig
}

func (m *KnownAccountModule) ID() string                { return "known-account" }
func (m *KnownAccountModule) Name() string              { return "AWS Known Account Lookup" }
func (m *KnownAccountModule) Platform() plugin.Platform { return plugin.PlatformAWS }
func (m *KnownAccountModule) Category() plugin.Category { return plugin.CategoryAnalyze }
func (m *KnownAccountModule) OpsecLevel() string        { return "safe" }
func (m *KnownAccountModule) Authors() []string         { return []string{"Praetorian"} }

func (m *KnownAccountModule) Description() string {
	return "Looks up an AWS account ID against known public account databases to identify the owning organization."
}

func (m *KnownAccountModule) References() []string {
	return []string{
		"https://github.com/rupertbg/aws-public-account-ids",
		"https://github.com/fwdcloudsec/known_aws_accounts",
	}
}

func (m *KnownAccountModule) SupportedResourceTypes() []string {
	return nil
}

func (m *KnownAccountModule) Parameters() any {
	return &m.KnownAccountConfig
}

// knownAccountEntry holds the matched account owner and source.
type knownAccountEntry struct {
	AccountID string `json:"account_id"`
	Owner     string `json:"owner"`
	Source    string `json:"source"`
}

func (m *KnownAccountModule) Run(cfg plugin.Config, out *pipeline.P[model.AurelianModel]) error {
	c := m.KnownAccountConfig

	cfg.Info("looking up account %s", c.AccountID)

	// Check Thinkst canary accounts first (no network required).
	if slices.Contains(thinkstCanaryAccounts, c.AccountID) {
		result := knownAccountEntry{
			AccountID: c.AccountID,
			Owner:     "Thinkst Canary Token",
			Source:    "hardcoded",
		}
		return emitKnownAccountResult(m.ID(), c.AccountID, result, out)
	}

	// Fetch from all three remote sources and return the first match.
	fetchers := []struct {
		name string
		fn   func(string) (knownAccountEntry, bool, error)
	}{
		{"rupertbg/aws-public-account-ids", func(id string) (knownAccountEntry, bool, error) {
			return lookupInJSONSource(id)
		}},
		{"fwdcloudsec/known_aws_accounts", func(id string) (knownAccountEntry, bool, error) {
			return lookupInYAMLSource(id, knownAccountsYAML1URL, "fwdcloudsec/known_aws_accounts")
		}},
		{"duo-labs/cloudmapper", func(id string) (knownAccountEntry, bool, error) {
			return lookupInYAMLSource(id, knownAccountsYAML2URL, "duo-labs/cloudmapper")
		}},
	}

	for _, f := range fetchers {
		cfg.Info("checking source: %s", f.name)
		entry, found, err := f.fn(c.AccountID)
		if err != nil {
			cfg.Warn("error checking %s: %v", f.name, err)
			continue
		}
		if found {
			return emitKnownAccountResult(m.ID(), c.AccountID, entry, out)
		}
	}

	// Not found in any source.
	result := knownAccountEntry{
		AccountID: c.AccountID,
		Owner:     "Unknown",
		Source:    "",
	}
	return emitKnownAccountResult(m.ID(), c.AccountID, result, out)
}

func emitKnownAccountResult(moduleID, accountID string, entry knownAccountEntry, out *pipeline.P[model.AurelianModel]) error {
	resultsJSON, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshaling results: %w", err)
	}

	out.Send(output.AnalyzeResult{
		Module:  moduleID,
		Input:   accountID,
		Results: json.RawMessage(resultsJSON),
	})

	return nil
}

// lookupInJSONSource fetches and searches the rupertbg JSON array source.
func lookupInJSONSource(accountID string) (knownAccountEntry, bool, error) {
	body, err := httpClient.Get(knownAccountsJSONURL)
	if err != nil {
		return knownAccountEntry{}, false, err
	}

	var accounts []struct {
		ID    string `json:"id"`
		Owner string `json:"owner"`
	}
	if err := json.Unmarshal(body, &accounts); err != nil {
		return knownAccountEntry{}, false, fmt.Errorf("parsing JSON: %w", err)
	}

	for _, a := range accounts {
		if a.ID == accountID {
			return knownAccountEntry{
				AccountID: accountID,
				Owner:     a.Owner,
				Source:    "rupertbg/aws-public-account-ids",
			}, true, nil
		}
	}

	return knownAccountEntry{}, false, nil
}

// yamlAccountEntry represents a single entry in the fwdcloudsec or cloudmapper YAML sources.
// Both sources use the same structure: a name field and an accounts array of account ID strings.
type yamlAccountEntry struct {
	Name     string   `yaml:"name"`
	Source   any      `yaml:"source"`
	Accounts []string `yaml:"accounts"`
}

// lookupInYAMLSource fetches and searches a YAML accounts file.
// Both fwdcloudsec and cloudmapper use a list of objects with a name field and an accounts array.
func lookupInYAMLSource(accountID, url, sourceName string) (knownAccountEntry, bool, error) {
	body, err := httpClient.Get(url)
	if err != nil {
		return knownAccountEntry{}, false, err
	}

	var entries []yamlAccountEntry
	if err := yaml.Unmarshal(body, &entries); err != nil {
		return knownAccountEntry{}, false, fmt.Errorf("parsing YAML from %s: %w", sourceName, err)
	}

	for _, e := range entries {
		for _, id := range e.Accounts {
			if id == accountID {
				return knownAccountEntry{
					AccountID: accountID,
					Owner:     e.Name,
					Source:    sourceName,
				}, true, nil
			}
		}
	}

	return knownAccountEntry{}, false, nil
}

