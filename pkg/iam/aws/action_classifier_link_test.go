package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/praetorian-inc/aurelian/pkg/types"
)

func TestAWSActionClassifierLink_Process(t *testing.T) {
	t.Run("Process valid action", func(t *testing.T) {
		action := "appsync:ListApiKeys"
		expected := make(map[string][]string)
		expected[action] = []string{"CredentialExposure"}

		link := NewAWSActionClassifierLink(map[string]any{})
		if err := link.Initialize(); err != nil {
			t.Fatalf("Failed to initialize link: %v", err)
		}

		outputs, err := link.Process(context.Background(), action)
		if err != nil {
			t.Fatalf("Process failed: %v", err)
		}

		if len(outputs) != 1 {
			t.Fatalf("Expected 1 output, got %d", len(outputs))
		}

		result, ok := outputs[0].(map[string][]string)
		if !ok {
			t.Fatalf("Expected map[string][]string output, got %T", outputs[0])
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
			t.Skipf("Skipping test: readonlyaccess.json not found: %v", err)
		}

		if err := json.Unmarshal(data, &roa); err != nil {
			t.Fatalf("Failed to unmarshal readonlyaccess.json: %v", err)
		}

		// Initialize links
		expandLink := NewAWSExpandActionsLink(map[string]any{})
		if err := expandLink.Initialize(); err != nil {
			t.Fatalf("Failed to initialize expand link: %v", err)
		}

		classifierLink := NewAWSActionClassifierLink(map[string]any{})
		if err := classifierLink.Initialize(); err != nil {
			t.Fatalf("Failed to initialize classifier link: %v", err)
		}

		ctx := context.Background()

		// Process each action through the chain
		for _, statement := range *roa.Statement {
			if statement.Effect == "Allow" {
				if statement.Action != nil {
					for _, action := range *statement.Action {
						// First expand the action
						expandedOutputs, err := expandLink.Process(ctx, action)
						if err != nil {
							t.Errorf("Failed to expand action %s: %v", action, err)
							continue
						}

						// Then classify each expanded action
						for _, expandedAction := range expandedOutputs {
							classifiedOutputs, err := classifierLink.Process(ctx, expandedAction)
							if err != nil {
								t.Errorf("Failed to classify action %v: %v", expandedAction, err)
								continue
							}

							// Log the results
							for _, result := range classifiedOutputs {
								if resultMap, ok := result.(map[string][]string); ok {
									fmt.Printf("%s \n", resultMap)
									t.Logf("%s \n", resultMap)
								}
							}
						}
					}
				}
			}
		}
	})
}
