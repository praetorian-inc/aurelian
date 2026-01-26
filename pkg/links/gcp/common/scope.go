package common

import (
	"fmt"

	"github.com/praetorian-inc/janus-framework/pkg/chain/cfg"
)

type ScopeConfig struct {
	Type  string
	Value string
}

func ParseScopeArgs(args map[string]any) (*ScopeConfig, error) {
	orgList, _ := cfg.As[[]string](args["org"])
	folderList, _ := cfg.As[[]string](args["folder"])
	projectList, _ := cfg.As[[]string](args["project"])

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
