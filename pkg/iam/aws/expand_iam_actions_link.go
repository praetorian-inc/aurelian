package aws

import (
	"encoding/json"
	"log/slog"
	"regexp"
	"strings"

	"github.com/praetorian-inc/janus/pkg/chain"
	"github.com/praetorian-inc/janus/pkg/chain/cfg"
	"github.com/praetorian-inc/nebula/pkg/utils"
)

// AWSExpandActions is a link that expands wildcard IAM actions
// by fetching the complete list of AWS actions from the AWS Policy Generator
type AWSExpandActions struct {
	*chain.Base
	allActions []string
}

// NewAWSExpandActionsLink creates a new AWSExpandActions link
func NewAWSExpandActionsLink(configs ...cfg.Config) chain.Link {
	a := &AWSExpandActions{}
	a.Base = chain.NewBase(a, configs...)
	return a
}

// Initialize fetches all AWS actions when the link is created
func (a *AWSExpandActions) Initialize() error {
	slog.Info("Initializing AWS Expand Actions link")
	var err error
	a.allActions, err = fetchAllAWSActions()
	if err != nil {
		slog.Error("Error fetching AWS actions during initialization", "error", err)
		return err
	}
	slog.Info("Successfully loaded AWS actions", "count", len(a.allActions))
	return nil
}

// Process expands wildcard IAM actions by matching against all known AWS actions
func (a *AWSExpandActions) Process(action string) error {
	service := strings.ToLower(strings.Split(action, ":")[0])
	act := strings.Split(action, ":")[1]

	// Create a case insensitive regex pattern from the input action wildcard
	pattern := strings.ReplaceAll(act, "*", ".*")
	pattern = "(?i)^" + service + ":" + pattern + "$"

	// Find and send all matching actions
	matchCount := 0
	for _, actionName := range a.allActions {
		match, _ := regexp.MatchString(pattern, actionName)
		if match {
			if err := a.Send(actionName); err != nil {
				return err
			}
			matchCount++
		}
	}

	slog.Debug("Expanded AWS action pattern", "pattern", action, "matches", matchCount)
	return nil
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
