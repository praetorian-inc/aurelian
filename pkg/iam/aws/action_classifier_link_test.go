package aws

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/nebula/pkg/types"
)

func TestAWSActionClassifierLink_Process(t *testing.T) {
	t.Run("Process valid action", func(t *testing.T) {
		action := "appsync:ListApiKeys"
		expected := make(map[string][]string)
		expected[action] = []string{"CredentialExposure"}
		c := chain.NewChain(NewAWSActionClassifierLink())
		c.Send(action)
		c.Close()

		var result map[string][]string
		for o, ok := chain.RecvAs[map[string][]string](c); ok; o, ok = chain.RecvAs[map[string][]string](c) {
			result = o
		}

		if !reflect.DeepEqual(result, expected) {
			t.Errorf("Expected %v, got %v", expected, result)
		}
	})
}

func TestAWSActionClassifierLink_FullPolicy(t *testing.T) {
	t.Setenv("GO_TEST_TIMEOUT", "60s")
	t.Run("Process full policy", func(t *testing.T) {
		var roa types.Policy
		data, err := os.ReadFile("readonlyaccess.json")
		if err != nil {
			t.Fatalf("Failed to read readonlyaccess.json: %v", err)
		}

		if err := json.Unmarshal(data, &roa); err != nil {
			t.Fatalf("Failed to unmarshal readonlyaccess.json: %v", err)
		}

		c := chain.NewChain(
			NewAWSExpandActionsLink(),
			NewAWSActionClassifierLink(),
		)

		for _, statement := range *roa.Statement {
			if statement.Effect == "Allow" {
				if statement.Action != nil {
					for _, action := range *statement.Action {
						c.Send(action)
					}
				}
			}
		}
		c.Close()

		for o, ok := chain.RecvAs[map[string][]string](c); ok; o, ok = chain.RecvAs[map[string][]string](c) {
			fmt.Printf("%s \n", o)
			t.Logf("%s \n", o)
		}
	})
}
