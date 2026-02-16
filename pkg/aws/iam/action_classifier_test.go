package iam

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestActionClassifier_Classify(t *testing.T) {
	classifier := &ActionClassifier{}

	t.Run("Classify valid action", func(t *testing.T) {
		action := "appsync:ListApiKeys"
		
		categories, found := classifier.Classify(action)
		require.True(t, found)
		
		expected := []string{"CredentialExposure"}
		assert.Equal(t, expected, categories)
	})

	t.Run("Classify unknown action", func(t *testing.T) {
		action := "fake:NonExistentAction"
		
		_, found := classifier.Classify(action)
		assert.False(t, found)
	})
}

func TestActionClassifier_FullPolicy(t *testing.T) {
	t.Setenv("GO_TEST_TIMEOUT", "60s")
	
	classifier := &ActionClassifier{}
	expander := &ActionExpander{}
	
	t.Run("Process full policy", func(t *testing.T) {
		var roa types.Policy
		data, err := os.ReadFile("readonlyaccess.json")
		if err != nil {
			t.Fatalf("Failed to read readonlyaccess.json: %v", err)
		}

		if err := json.Unmarshal(data, &roa); err != nil {
			t.Fatalf("Failed to unmarshal readonlyaccess.json: %v", err)
		}

		results := make(map[string][]string)
		
		for _, statement := range *roa.Statement {
			if statement.Effect == "Allow" {
				if statement.Action != nil {
					for _, action := range *statement.Action {
						// Expand action
						expandedActions, err := expander.Expand(action)
						require.NoError(t, err)
						
						// Classify each expanded action
						for _, expandedAction := range expandedActions {
							categories, found := classifier.Classify(expandedAction)
							if found {
								results[expandedAction] = categories
								t.Logf("%s: %v\n", expandedAction, categories)
							}
						}
					}
				}
			}
		}
		
		assert.NotEmpty(t, results, "Expected to classify at least some actions from ReadOnlyAccess policy")
	})
}
