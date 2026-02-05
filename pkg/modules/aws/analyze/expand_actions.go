package analyze

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/praetorian-inc/aurelian/pkg/plugin"
	"github.com/praetorian-inc/aurelian/pkg/utils"
)

func init() {
	plugin.Register(&ExpandActionsModule{})
}

// ExpandActionsModule expands wildcard AWS IAM actions to include all possible actions
type ExpandActionsModule struct {
	allActions []string
}

func (m *ExpandActionsModule) ID() string {
	return "expand-actions"
}

func (m *ExpandActionsModule) Name() string {
	return "AWS Expand Actions"
}

func (m *ExpandActionsModule) Description() string {
	return "Expand AWS IAM actions to include all possible actions by matching wildcard patterns against the complete AWS action list."
}

func (m *ExpandActionsModule) Platform() plugin.Platform {
	return plugin.PlatformAWS
}

func (m *ExpandActionsModule) Category() plugin.Category {
	return plugin.CategoryAnalyze
}

func (m *ExpandActionsModule) OpsecLevel() string {
	return "low"
}

func (m *ExpandActionsModule) Authors() []string {
	return []string{"Praetorian"}
}

func (m *ExpandActionsModule) References() []string {
	return []string{
		"https://awspolicygen.s3.amazonaws.com/js/policies.js",
	}
}

func (m *ExpandActionsModule) Parameters() []plugin.Parameter {
	return []plugin.Parameter{
		{
			Name:        "action",
			Description: "AWS IAM action pattern to expand (supports wildcards: *, s3:*, ec2:Describe*)",
			Type:        "string",
			Required:    true,
		},
	}
}

func (m *ExpandActionsModule) Run(cfg plugin.Config) ([]plugin.Result, error) {
	// Get action parameter
	action, ok := cfg.Args["action"].(string)
	if !ok || action == "" {
		return nil, fmt.Errorf("action parameter is required")
	}

	// Fetch all AWS actions if not already loaded
	if m.allActions == nil {
		var err error
		m.allActions, err = fetchAllAWSActions()
		if err != nil {
			return nil, fmt.Errorf("failed to fetch AWS actions: %w", err)
		}
	}

	// If no wildcard, return the action as-is
	if !strings.Contains(action, "*") {
		return []plugin.Result{
			{
				Data: map[string]any{
					"pattern": action,
					"matches": []string{action},
					"count":   1,
				},
				Metadata: map[string]any{
					"module":      "expand-actions",
					"platform":    "aws",
					"opsec_level": "low",
				},
			},
		}, nil
	}

	// Parse service and action parts
	var service, act string
	if action == "*" {
		service = "*"
		act = "*"
	} else {
		parts := strings.Split(action, ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid action format: expected 'service:action', got '%s'", action)
		}
		service = strings.ToLower(parts[0])
		act = parts[1]
	}

	// Build and compile regex pattern
	pattern := strings.ReplaceAll(act, "*", ".*")
	regexPattern := "(?i)^" + service + ":" + pattern + "$"
	regex, err := regexp.Compile(regexPattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern: %w", err)
	}

	// Find all matching actions
	var matches []string
	for _, actionName := range m.allActions {
		if regex.MatchString(actionName) {
			matches = append(matches, actionName)
		}
	}

	// Build result
	data := map[string]any{
		"pattern": action,
		"matches": matches,
		"count":   len(matches),
	}

	return []plugin.Result{
		{
			Data: data,
			Metadata: map[string]any{
				"module":      "expand-actions",
				"platform":    "aws",
				"opsec_level": "low",
			},
		},
	}, nil
}

// fetchAllAWSActions fetches the list of all AWS actions from the AWS Policy Generator
func fetchAllAWSActions() ([]string, error) {
	body, err := utils.Cached_httpGet("https://awspolicygen.s3.amazonaws.com/js/policies.js")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch AWS policies: %w", err)
	}

	// Remove the JavaScript assignment to get valid JSON
	jstring := strings.Replace(string(body), "app.PolicyEditorConfig=", "", 1)

	var j map[string]interface{}
	err = json.Unmarshal([]byte(jstring), &j)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AWS policies JSON: %w", err)
	}

	// Extract all actions from the service map
	allActions := []string{}
	serviceMap, ok := j["serviceMap"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("serviceMap not found in AWS policies")
	}

	for serviceName := range serviceMap {
		serviceData, ok := serviceMap[serviceName].(map[string]interface{})
		if !ok {
			continue
		}

		prefix, ok := serviceData["StringPrefix"].(string)
		if !ok {
			continue
		}

		actions, ok := serviceData["Actions"].([]interface{})
		if !ok {
			continue
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
