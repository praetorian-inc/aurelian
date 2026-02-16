package iam

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

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
		ae.allActions, ae.initErr = fetchAllAWSActions()
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
		parts := strings.SplitN(pattern, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid action pattern: %s", pattern)
		}
		service = strings.ToLower(parts[0])
		act = parts[1]
	}

	// Precompile regex outside the loop
	regexStr := strings.ReplaceAll(act, "*", ".*")
	regexPattern := "(?i)^" + service + ":" + regexStr + "$"
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

// fetchAllAWSActions fetches the list of all AWS actions from the AWS types.Policy Generator
func fetchAllAWSActions() ([]string, error) {
	resp, err := http.Get("https://awspolicygen.s3.amazonaws.com/js/policies.js")
	if err != nil {
		return nil, fmt.Errorf("fetching AWS actions: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading AWS actions response: %w", err)
	}

	// Remove the JavaScript assignment to get valid JSON
	jstring := strings.Replace(string(body), "app.PolicyEditorConfig=", "", 1)

	var j map[string]interface{}
	err = json.Unmarshal([]byte(jstring), &j)
	if err != nil {
		return nil, fmt.Errorf("parsing AWS actions JSON: %w", err)
	}

	// Extract all actions from the service map
	var allActions []string
	serviceMap, ok := j["serviceMap"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("unexpected serviceMap format")
	}
	for serviceName := range serviceMap {
		svc := serviceMap[serviceName].(map[string]interface{})
		prefix := svc["StringPrefix"].(string)
		actions := svc["Actions"].([]interface{})
		for _, a := range actions {
			action := a.(string)
			allActions = append(allActions, prefix+":"+action)
		}
	}

	return allActions, nil
}
