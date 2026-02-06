package common

import (
	"fmt"
)

type ScopeConfig struct {
	Type  string
	Value string
}

// getStringSlice extracts a []string from map[string]any, supporting both []string and []any
func getStringSlice(args map[string]any, key string) []string {
	val, exists := args[key]
	if !exists {
		return nil
	}

	// Direct []string case
	if strSlice, ok := val.([]string); ok {
		return strSlice
	}

	// []any case - convert to []string
	if anySlice, ok := val.([]any); ok {
		result := make([]string, 0, len(anySlice))
		for _, item := range anySlice {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}

	return nil
}

func ParseScopeArgs(args map[string]any) (*ScopeConfig, error) {
	orgList := getStringSlice(args, "org")
	folderList := getStringSlice(args, "folder")
	projectList := getStringSlice(args, "project")

	scopeCount := 0
	scope := &ScopeConfig{}

	if len(orgList) > 0 {
		scopeCount++
		scope.Type = "org"
		scope.Value = orgList[0]
	}
	if len(folderList) > 0 {
		scopeCount++
		scope.Type = "folder"
		scope.Value = folderList[0]
	}
	if len(projectList) > 0 {
		scopeCount++
		scope.Type = "project"
		scope.Value = projectList[0]
	}

	if scopeCount == 0 {
		return nil, fmt.Errorf("must provide exactly one of --org, --folder, or --project")
	}
	if scopeCount > 1 {
		return nil, fmt.Errorf("must provide exactly one of --org, --folder, or --project (got %d)", scopeCount)
	}

	return scope, nil
}
