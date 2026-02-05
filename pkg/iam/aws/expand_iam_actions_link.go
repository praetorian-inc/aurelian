package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/utils"
)

// AWSExpandActions is a link that expands wildcard IAM actions
// by fetching the complete list of AWS actions from the AWS Policy Generator
type AWSExpandActions struct {
	*plugin.BaseLink
	allActions []string
}

// NewAWSExpandActionsLink creates a new AWSExpandActions link
func NewAWSExpandActionsLink(args map[string]any) *AWSExpandActions {
	a := &AWSExpandActions{
		BaseLink: plugin.NewBaseLink("aws-expand-actions", args),
	}
	return a
}

// Initialize fetches all AWS actions when the link is created
func (a *AWSExpandActions) Initialize() error {
	a.Logger().Debug("Initializing AWS Expand Actions link")
	var err error
	a.allActions, err = fetchAllAWSActions()
	if err != nil {
		a.Logger().Error("Error fetching AWS actions during initialization", "error", err)
		return err
	}
	a.Logger().Debug("Successfully loaded AWS actions", "count", len(a.allActions))
	return nil
}

// Process expands wildcard IAM actions by matching against all known AWS actions
func (a *AWSExpandActions) Process(ctx context.Context, input any) ([]any, error) {
	action, ok := input.(string)
	if !ok {
		return nil, fmt.Errorf("expected string input, got %T", input)
	}

	if !strings.Contains(action, "*") {
		a.Logger().Debug("No wildcard in action, skipping expansion", "action", action)
		a.Send(action)
		return a.Outputs(), nil
	}

	a.Logger().Debug("Expanding AWS action pattern", "pattern", action)
	var service, act string
	if action == "*" {
		service = "*"
		act = "*"
	} else {
		service = strings.ToLower(strings.Split(action, ":")[0])
		act = strings.Split(action, ":")[1]
	}

	// Precompile regex outside the loop
	pattern := strings.ReplaceAll(act, "*", ".*")
	regexPattern := "(?i)^" + service + ":" + pattern + "$"
	regex, err := regexp.Compile(regexPattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %s", err)
	}

	// Find and send all matching actions
	matchCount := 0
	for _, actionName := range a.allActions {
		if regex.MatchString(actionName) {
			a.Send(actionName)
			matchCount++
		}
	}

	a.Logger().Debug("Expanded AWS action pattern", "pattern", action, "matches", matchCount)
	return a.Outputs(), nil
}

// fetchAllAWSActions fetches the list of all AWS actions from the AWS Policy Generator
func fetchAllAWSActions() ([]string, error) {
	body, err := utils.Cached_httpGet("https://awspolicygen.s3.amazonaws.com/js/policies.js")
	if err != nil {
		return nil, err
	}

	// Remove the JavaScript assignment to get valid JSON
	jstring := strings.Replace(string(body), "app.PolicyEditorConfig=", "", 1)

	var j map[string]interface{}
	err = json.Unmarshal([]byte(jstring), &j)
	if err != nil {
		return nil, err
	}

	// Extract all actions from the service map
	allActions := []string{}
	for serviceName := range j["serviceMap"].(map[string]interface{}) {
		prefix := j["serviceMap"].(map[string]interface{})[serviceName].(map[string]interface{})["StringPrefix"].(string)
		actions := j["serviceMap"].(map[string]interface{})[serviceName].(map[string]interface{})["Actions"].([]interface{})
		for _, a := range actions {
			action := a.(string)
			allActions = append(allActions, prefix+":"+action)
		}
	}

	return allActions, nil
}
