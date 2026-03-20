package iam

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"

	"github.com/praetorian-inc/aurelian/pkg/utils"
)

var httpClient = &utils.CachedHTTPClient{}

// ActionExpander expands wildcard IAM actions by fetching the complete list
// of AWS actions from the AWS types.Policy Generator. Replaces Janus AWSExpandActions chain link.
type ActionExpander struct {
	allActions []string
	once       sync.Once
	initErr    error
}

// Expand takes an IAM action pattern (potentially with wildcards) and returns
// all matching concrete actions. Lazy-initializes on first call.
func (ae *ActionExpander) Expand(pattern string) ([]string, error) {
	ae.once.Do(func() {
		ae.allActions, ae.initErr = ae.fetchAllAWSActions()
		if ae.initErr != nil {
			slog.Error("Error fetching AWS actions during initialization", "error", ae.initErr)
		} else {
			slog.Debug("Successfully loaded AWS actions", "count", len(ae.allActions))
		}
	})
	if ae.initErr != nil {
		return nil, ae.initErr
	}

	if !strings.Contains(pattern, "*") {
		return []string{pattern}, nil
	}

	slog.Debug("Expanding AWS action pattern", "pattern", pattern)
	var service, act string
	if pattern == "*" {
		service = "*"
		act = "*"
	} else {
		var ok bool
		service, act, ok = strings.Cut(pattern, ":")
		if !ok {
			return nil, fmt.Errorf("invalid action pattern: %s", pattern)
		}
		service = strings.ToLower(service)
	}

	// Precompile regex outside the loop — QuoteMeta to safely handle any metacharacters
	escaped := regexp.QuoteMeta(service + ":" + act)
	regexPattern := "(?i)^" + strings.ReplaceAll(escaped, `\*`, `.*`) + "$"
	re, err := regexp.Compile(regexPattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %w", err)
	}

	var results []string
	for _, actionName := range ae.allActions {
		if re.MatchString(actionName) {
			results = append(results, actionName)
		}
	}

	slog.Debug("Expanded AWS action pattern", "pattern", pattern, "matches", len(results))
	return results, nil
}

const awsPolicyGenURL = "https://awspolicygen.s3.amazonaws.com/js/policies.js"

func (ae *ActionExpander) fetchAllAWSActions() ([]string, error) {
	body, err := httpClient.Get(awsPolicyGenURL)
	if err != nil {
		return nil, fmt.Errorf("fetching AWS actions: %w", err)
	}

	// Remove the JavaScript assignment to get valid JSON
	jstring := strings.Replace(string(body), "app.PolicyEditorConfig=", "", 1)

	var j map[string]any
	err = json.Unmarshal([]byte(jstring), &j)
	if err != nil {
		return nil, fmt.Errorf("parsing AWS actions JSON: %w", err)
	}

	// Extract all actions from the service map
	var allActions []string
	serviceMap, ok := j["serviceMap"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected serviceMap format")
	}
	for serviceName, raw := range serviceMap {
		svc, ok := raw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("unexpected format for service %q", serviceName)
		}
		prefix, ok := svc["StringPrefix"].(string)
		if !ok {
			return nil, fmt.Errorf("missing StringPrefix for service %q", serviceName)
		}
		actions, ok := svc["Actions"].([]any)
		if !ok {
			return nil, fmt.Errorf("missing Actions for service %q", serviceName)
		}
		for _, a := range actions {
			action, ok := a.(string)
			if !ok {
				continue
			}
			allActions = append(allActions, prefix+":"+action)
		}
	}

	return allActions, nil
}
