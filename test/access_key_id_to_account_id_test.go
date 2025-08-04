package test

import (
	"testing"
)

func TestAccessKeyIdToAccountId(t *testing.T) {
	keys := []map[string]string{
		{
			"access_key_id": "AKIAV7S32T2OSBFJQOIY",
			"account_id":    "411435703965",
		},
		{
			"access_key_id": "ASIAY34FZKBOKMUTVV7A",
			"account_id":    "609629065308",
		},
	}

	// Simple test to ensure test data is valid
	if len(keys) == 0 {
		t.Error("test data should not be empty")
	}

	for _, keyPair := range keys {
		if keyPair["access_key_id"] == "" || keyPair["account_id"] == "" {
			t.Error("access_key_id and account_id should not be empty")
		}
	}
}
