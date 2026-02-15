package iam

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
)

// AwsData represents the IAM dataset structure from iann0036/iam-dataset
type AwsData struct {
	Api      map[string][]string `json:"api"`
	ApiLower map[string][]string `json:"api_lower"`
	Iam      map[string][]string `json:"iam"`
	IamLower map[string][]string `json:"iam_lower"`
}

// ActionClassifier classifies IAM actions into categories (e.g., "read", "write", "list", "tagging").
// Replaces Janus AWSActionClassifierLink chain link.
type ActionClassifier struct {
	actionMap map[string][]string
	once      sync.Once
	initErr   error
}

// Classify returns the categories for a given IAM action and whether it was found.
// Lazy-initializes on first call.
func (ac *ActionClassifier) Classify(action string) ([]string, bool) {
	ac.once.Do(func() {
		ac.actionMap, ac.initErr = loadActionClassifications()
		if ac.initErr != nil {
			slog.Error("Error loading action classifications", "error", ac.initErr)
		}
	})
	if ac.initErr != nil {
		return nil, false
	}

	keys, exists := ac.actionMap[strings.ToLower(action)]
	return keys, exists
}

func loadActionClassifications() (map[string][]string, error) {
	resp, err := http.Get("https://raw.githubusercontent.com/iann0036/iam-dataset/refs/heads/main/aws/tags.json")
	if err != nil {
		return nil, fmt.Errorf("downloading IAM dataset: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading IAM dataset response: %w", err)
	}

	var awsData AwsData
	if err := json.Unmarshal(body, &awsData); err != nil {
		return nil, fmt.Errorf("parsing IAM dataset JSON: %w", err)
	}

	return createActionMap(&awsData), nil
}

func createActionMap(data *AwsData) map[string][]string {
	actionMap := make(map[string][]string)

	addActionsToMap := func(sourceMap map[string][]string) {
		for category, actions := range sourceMap {
			for _, action := range actions {
				if action == "" {
					continue
				}

				existing := actionMap[action]
				existing = append(existing, category)
				slices.Sort(existing)
				existing = slices.Compact(existing)
				actionMap[action] = existing
			}
		}
	}

	addActionsToMap(data.ApiLower)
	addActionsToMap(data.IamLower)

	return actionMap
}
