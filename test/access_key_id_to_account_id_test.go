package test

import (
	"context"
	"strconv"
	"testing"

	"github.com/praetorian-inc/nebula/pkg/stages"
)

func TestAccessKeyIdToAccountIdStage(t *testing.T) {

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
	for _, key := range keys {
		out := stages.AwsAccessKeyIdtoAccountIdStage(context.Background(), nil, stages.Generator([]string{key["access_key_id"]}))
		result := <-out
		if strconv.Itoa(result) != key["account_id"] {
			t.Errorf("Expected %s, but got %d", key["account_id"], result)
		}

	}

}
