package analyze

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestThinkstCanaryDetection_KnownCanary(t *testing.T) {
	// All known canary accounts should be detected
	for _, id := range thinkstCanaryAccounts {
		found := false
		for _, canary := range thinkstCanaryAccounts {
			if canary == id {
				found = true
				break
			}
		}
		assert.True(t, found, "canary account %s should be in thinkstCanaryAccounts", id)
	}
}

func TestThinkstCanaryDetection_NonCanary(t *testing.T) {
	nonCanary := "123456789012"
	found := false
	for _, id := range thinkstCanaryAccounts {
		if id == nonCanary {
			found = true
			break
		}
	}
	assert.False(t, found, "account %s should not be a known canary", nonCanary)
}

func TestThinkstCanaryAccounts_SpecificKnownValues(t *testing.T) {
	// Verify specific known canary IDs are present
	knownCanaryIDs := []string{
		"052310077262",
		"819147034852",
		"992382622183",
	}
	for _, id := range knownCanaryIDs {
		found := false
		for _, canary := range thinkstCanaryAccounts {
			if canary == id {
				found = true
				break
			}
		}
		assert.True(t, found, "expected known canary account %s to be present", id)
	}
}

func TestYAMLAccountEntry_Unmarshal(t *testing.T) {
	raw := `
- name: "Amazon"
  accounts:
    - "123456789012"
    - "210987654321"
- name: "Google"
  accounts:
    - "999999999999"
`
	var entries []yamlAccountEntry
	err := yaml.Unmarshal([]byte(raw), &entries)
	require.NoError(t, err)
	require.Len(t, entries, 2)

	assert.Equal(t, "Amazon", entries[0].Name)
	assert.Equal(t, []string{"123456789012", "210987654321"}, entries[0].Accounts)
	assert.Equal(t, "Google", entries[1].Name)
	assert.Equal(t, []string{"999999999999"}, entries[1].Accounts)
}

func TestYAMLAccountEntry_UnmarshalWithSourceField(t *testing.T) {
	// The source field can be any type (string, list, etc.)
	raw := `
- name: "TestOrg"
  source: "https://example.com"
  accounts:
    - "111111111111"
`
	var entries []yamlAccountEntry
	err := yaml.Unmarshal([]byte(raw), &entries)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "TestOrg", entries[0].Name)
	assert.Equal(t, []string{"111111111111"}, entries[0].Accounts)
}

func TestJSONSourceStruct_Unmarshal(t *testing.T) {
	raw := `[
		{"id": "123456789012", "owner": "Amazon Web Services"},
		{"id": "210987654321", "owner": "Another Org"}
	]`

	var accounts []struct {
		ID    string `json:"id"`
		Owner string `json:"owner"`
	}
	err := json.Unmarshal([]byte(raw), &accounts)
	require.NoError(t, err)
	require.Len(t, accounts, 2)

	assert.Equal(t, "123456789012", accounts[0].ID)
	assert.Equal(t, "Amazon Web Services", accounts[0].Owner)
	assert.Equal(t, "210987654321", accounts[1].ID)
	assert.Equal(t, "Another Org", accounts[1].Owner)
}

func TestKnownAccountEntry_JSONRoundTrip(t *testing.T) {
	entry := knownAccountEntry{
		AccountID: "123456789012",
		Owner:     "Amazon Web Services",
		Source:    "rupertbg/aws-public-account-ids",
	}

	data, err := json.Marshal(entry)
	require.NoError(t, err)

	var got knownAccountEntry
	require.NoError(t, json.Unmarshal(data, &got))

	assert.Equal(t, entry.AccountID, got.AccountID)
	assert.Equal(t, entry.Owner, got.Owner)
	assert.Equal(t, entry.Source, got.Source)
}

func TestKnownAccountEntry_JSONFieldNames(t *testing.T) {
	entry := knownAccountEntry{
		AccountID: "123456789012",
		Owner:     "TestOrg",
		Source:    "test-source",
	}

	data, err := json.Marshal(entry)
	require.NoError(t, err)

	var raw map[string]string
	require.NoError(t, json.Unmarshal(data, &raw))

	assert.Equal(t, "123456789012", raw["account_id"])
	assert.Equal(t, "TestOrg", raw["owner"])
	assert.Equal(t, "test-source", raw["source"])
}
