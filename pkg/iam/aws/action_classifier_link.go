package aws

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/praetorian-inc/janus-framework/pkg/chain"
	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

//https://raw.githubusercontent.com/iann0036/iam-dataset/refs/heads/main/aws/tags.json

type AwsData struct {
	Api      map[string][]string `json:"api"`
	ApiLower map[string][]string `json:"api_lower"`
	Iam      map[string][]string `json:"iam"`
	IamLower map[string][]string `json:"iam_lower"`
}

func createActionMap(data *AwsData) map[string][]string {
	actionMap := make(map[string][]string)

	// Helper function to add actions to the map
	addActionsToMap := func(sourceMap map[string][]string) {
		for category, actions := range sourceMap {
			for _, action := range actions {
				// Skip empty strings
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

	// Add actions from api_lower
	addActionsToMap(data.ApiLower)

	// Add actions from iam_lower
	addActionsToMap(data.IamLower)

	return actionMap
}

type AWSActionClassifierLink struct {
	*chain.Base
	actionMap map[string][]string
	wg        sync.WaitGroup
}

func NewAWSActionClassifierLink(configs ...cfg.Config) chain.Link {
	a := &AWSActionClassifierLink{
		wg: sync.WaitGroup{},
	}
	a.Base = chain.NewBase(a, configs...)
	return a
}

func (a *AWSActionClassifierLink) Initialize() error {
	a.actionMap = make(map[string][]string)
	body, err := utils.Cached_httpGet("https://raw.githubusercontent.com/iann0036/iam-dataset/refs/heads/main/aws/tags.json")
	if err != nil {
		return fmt.Errorf("error downloading file: %w", err)
	}

	// Parse the JSON
	var awsData AwsData
	if err := json.Unmarshal(body, &awsData); err != nil {
		return fmt.Errorf("error parsing JSON: %w", err)
	}

	// Create the action map
	a.actionMap = createActionMap(&awsData)

	return nil
}

func (a *AWSActionClassifierLink) Process(action string) error {
	if keys, exists := a.actionMap[strings.ToLower(action)]; exists {
		m := make(map[string][]string)
		m[action] = keys
		if err := a.Send(m); err != nil {
			return fmt.Errorf("error sending keys: %w", err)
		}
	}

	return nil
}
