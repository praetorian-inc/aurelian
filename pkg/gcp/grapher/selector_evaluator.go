package gcloudiam

import (
	"strings"

	"github.com/google/cel-go/cel"
	gcptypes "github.com/praetorian-inc/nebula/pkg/types/gcp"
)

type SelectorEvaluator struct {
	celEnv *cel.Env
}

func NewSelectorEvaluator() (*SelectorEvaluator, error) {
	env, err := cel.NewEnv(
		cel.Variable("resource", cel.DynType),
		cel.Variable("request", cel.DynType),
	)
	if err != nil {
		return nil, err
	}
	return &SelectorEvaluator{celEnv: env}, nil
}

func (se *SelectorEvaluator) EvaluateCondition(condition *gcptypes.Condition, resource *gcptypes.Resource) bool {
	if condition == nil || condition.Expression == "" {
		return true
	}
	ast, issues := se.celEnv.Compile(condition.Expression)
	if issues != nil && issues.Err() != nil {
		return false
	}
	prg, err := se.celEnv.Program(ast)
	if err != nil {
		return false
	}
	vars := map[string]any{
		"resource": map[string]any{
			"name":     resource.URI,
			"type":     resource.AssetType,
			"service":  resource.Service,
			"location": resource.Location,
			"labels":   resource.Properties,
		},
	}
	result, _, err := prg.Eval(vars)
	if err != nil {
		return false
	}
	if boolResult, ok := result.Value().(bool); ok {
		return boolResult
	}
	return false
}

func (se *SelectorEvaluator) MatchesResourceType(selector string, resource *gcptypes.Resource) bool {
	if selector == "" {
		return true
	}
	return strings.Contains(resource.AssetType, selector)
}

func (se *SelectorEvaluator) MatchesService(service string, resource *gcptypes.Resource) bool {
	if service == "" {
		return true
	}
	return resource.Service == service
}

func (se *SelectorEvaluator) MatchesTags(requiredTags map[string]string, resource *gcptypes.Resource) bool {
	if len(requiredTags) == 0 {
		return true
	}
	for key, value := range requiredTags {
		resourceValue, ok := resource.Properties[key]
		if !ok || resourceValue != value {
			return false
		}
	}
	return true
}
