package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/praetorian-inc/aurelian/pkg/links/aws/base"
	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/utils"
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
	*base.NativeAWSLink
	actionMap map[string][]string
	wg        sync.WaitGroup
}

func NewAWSActionClassifierLink(args map[string]any) *AWSActionClassifierLink {
	return &AWSActionClassifierLink{
		NativeAWSLink: base.NewNativeAWSLink("action-classifier", args),
		wg:            sync.WaitGroup{},
	}
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

func (a *AWSActionClassifierLink) Process(ctx context.Context, input any) ([]any, error) {
	action, ok := input.(string)
	if !ok {
		return nil, fmt.Errorf("expected string input, got %T", input)
	}

	if keys, exists := a.actionMap[strings.ToLower(action)]; exists {
		m := make(map[string][]string)
		m[action] = keys
		a.Send(m)
	}

	return a.Outputs(), nil
}

func (a *AWSActionClassifierLink) Parameters() []plugin.Parameter {
	return []plugin.Parameter{}
}
