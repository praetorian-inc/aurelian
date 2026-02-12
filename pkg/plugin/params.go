// Package plugin provides the core plugin architecture for Aurelian modules.
package plugin

import (
	"fmt"
	"regexp"
	"strings"
)

// Parameter describes a module parameter
type Parameter struct {
	Name        string
	Description string
	Type        string // "string", "int", "bool", "[]string"
	Required    bool
	Default     any
	Shortcode   string
	Hidden      bool           // Hide from help output
	Pattern     *regexp.Regexp // Regex validation for string values
	Enum        []string       // Allowed values (case-insensitive)
	Sensitive   bool           // Mask in logs and help text
	Value       any            // Runtime value
	IsSet       bool           // Whether explicitly provided
}

// EffectiveValue returns the explicitly set value, or the default, or nil.
func (p *Parameter) EffectiveValue() any {
	if p.IsSet {
		return p.Value
	}
	if p.Default != nil {
		return p.Default
	}
	return nil
}

// Parameters is a typed, validated parameter collection.
type Parameters struct {
	params           []Parameter
	requiredTogether [][]string
	mutualExclusive  [][]string
}

// NewParameters creates a Parameters set from the given parameters.
func NewParameters(params ...Parameter) Parameters {
	return Parameters{params: params}
}

// Set assigns a value to the named parameter and marks it as explicitly set.
func (ps *Parameters) Set(name string, value any) {
	for i := range ps.params {
		if ps.params[i].Name == name {
			ps.params[i].Value = value
			ps.params[i].IsSet = true
			return
		}
	}
}

// IsSet reports whether the named parameter was explicitly provided.
func (ps *Parameters) IsSet(name string) bool {
	for i := range ps.params {
		if ps.params[i].Name == name {
			return ps.params[i].IsSet
		}
	}
	return false
}

// Validate checks all constraints: required fields, patterns, enums, and group rules.
func (ps *Parameters) Validate() error {
	for _, p := range ps.params {
		ev := p.EffectiveValue()

		if p.Required && !p.IsSet && p.Default == nil {
			return fmt.Errorf("required parameter %q is not set", p.Name)
		}

		if p.Pattern != nil && ev != nil {
			if s, ok := ev.(string); ok && s != "" {
				if !p.Pattern.MatchString(s) {
					return fmt.Errorf("parameter %q value %q does not match pattern %s", p.Name, s, p.Pattern.String())
				}
			}
		}

		if len(p.Enum) > 0 && ev != nil {
			if err := checkEnum(p.Name, ev, p.Enum); err != nil {
				return err
			}
		}
	}

	for _, group := range ps.requiredTogether {
		anySet, allSet := false, true
		for _, name := range group {
			if ps.IsSet(name) {
				anySet = true
			} else {
				allSet = false
			}
		}
		if anySet && !allSet {
			return fmt.Errorf("parameters %v must be set together", group)
		}
	}

	for _, group := range ps.mutualExclusive {
		setCount := 0
		for _, name := range group {
			if ps.IsSet(name) {
				setCount++
			}
		}
		if setCount > 1 {
			return fmt.Errorf("parameters %v are mutually exclusive", group)
		}
	}

	return nil
}

func checkEnum(name string, value any, allowed []string) error {
	var values []string
	switch v := value.(type) {
	case string:
		if v == "" {
			return nil
		}
		for _, part := range strings.Split(v, ",") {
			values = append(values, strings.TrimSpace(part))
		}
	case []string:
		values = v
	default:
		return nil
	}

	for _, val := range values {
		found := false
		for _, a := range allowed {
			if strings.EqualFold(val, a) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("parameter %q value %q is not one of allowed values: %v", name, val, allowed)
		}
	}
	return nil
}
