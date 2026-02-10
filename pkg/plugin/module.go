// Package plugin provides the core plugin architecture for Aurelian modules.
// This replaces the dependency on the Janus framework with a simple, standalone
// plugin system inspired by Nerva's architecture.
package plugin

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Platform represents the cloud platform or service category
type Platform string

const (
	PlatformAWS   Platform = "aws"
	PlatformAzure Platform = "azure"
	PlatformGCP   Platform = "gcp"
	PlatformSaaS  Platform = "saas"
)

// Category represents the module category
type Category string

const (
	CategoryRecon   Category = "recon"
	CategoryAnalyze Category = "analyze"
	CategorySecrets Category = "secrets"
)

const (
	AnyResourceType = "any"
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

// Config holds runtime configuration for a module
type Config struct {
	Args    map[string]any  // Runtime arguments (backward compat)
	Params  Parameters      // Typed parameter set
	Context context.Context // Execution context
	Output  io.Writer       // Output destination
	Verbose bool            // Verbose logging
}

// Parameters is a typed, validated parameter collection.
type Parameters struct {
	params           []Parameter
	requiredTogether [][]string
	mutualExclusive  [][]string
}

// SupportedResourceTypesProvider is an optional interface for modules that scope
// their supported resource types.
type SupportedResourceTypesProvider interface {
	SupportedResourceTypes() []string
}

// SupportedResourceTypes returns the resource types supported by a module, if declared.
func SupportedResourceTypes(m Module) []string {
	if provider, ok := m.(SupportedResourceTypesProvider); ok {
		return provider.SupportedResourceTypes()
	}

	return []string{}
}

// NewParameters creates a Parameters set from the given parameters.
func NewParameters(params ...Parameter) Parameters {
	return Parameters{params: params}
}

// Add appends parameters and returns the updated set.
func (ps Parameters) Add(params ...Parameter) Parameters {
	ps.params = append(ps.params, params...)
	return ps
}

// RequiredTogether declares a group of parameters that must all be set if any one is.
func (ps Parameters) RequiredTogether(names ...string) Parameters {
	ps.requiredTogether = append(ps.requiredTogether, names)
	return ps
}

// MutuallyExclusive declares a group of parameters where at most one may be set.
func (ps Parameters) MutuallyExclusive(names ...string) Parameters {
	ps.mutualExclusive = append(ps.mutualExclusive, names)
	return ps
}

// RequiredTogetherGroups returns the required-together constraint groups.
func (ps Parameters) RequiredTogetherGroups() [][]string {
	return ps.requiredTogether
}

// MutuallyExclusiveGroups returns the mutually-exclusive constraint groups.
func (ps Parameters) MutuallyExclusiveGroups() [][]string {
	return ps.mutualExclusive
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

// All returns every parameter in the set.
func (ps *Parameters) All() []Parameter {
	return ps.params
}

// Len returns the number of parameters.
func (ps *Parameters) Len() int {
	return len(ps.params)
}

// String returns the effective string value for the named parameter.
func (ps *Parameters) String(name string) string {
	for i := range ps.params {
		if ps.params[i].Name == name {
			v := ps.params[i].EffectiveValue()
			if v == nil {
				return ""
			}
			s, _ := v.(string)
			return s
		}
	}
	return ""
}

// Int returns the effective int value for the named parameter.
func (ps *Parameters) Int(name string) int {
	for i := range ps.params {
		if ps.params[i].Name == name {
			v := ps.params[i].EffectiveValue()
			if v == nil {
				return 0
			}
			n, _ := v.(int)
			return n
		}
	}
	return 0
}

// Bool returns the effective bool value for the named parameter.
func (ps *Parameters) Bool(name string) bool {
	for i := range ps.params {
		if ps.params[i].Name == name {
			v := ps.params[i].EffectiveValue()
			if v == nil {
				return false
			}
			b, _ := v.(bool)
			return b
		}
	}
	return false
}

// StringSlice returns the effective []string value for the named parameter.
func (ps *Parameters) StringSlice(name string) []string {
	for i := range ps.params {
		if ps.params[i].Name == name {
			v := ps.params[i].EffectiveValue()
			if v == nil {
				return nil
			}
			ss, _ := v.([]string)
			return ss
		}
	}
	return nil
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

// ToArgs converts the parameter set to a map for backward compatibility.
func (ps *Parameters) ToArgs() map[string]any {
	args := make(map[string]any, len(ps.params))
	for _, p := range ps.params {
		v := p.EffectiveValue()
		if v != nil {
			args[p.Name] = v
		}
	}
	return args
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

// Result is the standardized output type for all modules
type Result struct {
	Data     any            // The actual result data
	Metadata map[string]any // Additional metadata
	Error    error          // Any error that occurred
}

// Module is the core interface that all Aurelian modules implement
type Module interface {
	// Metadata
	ID() string
	Name() string
	Description() string
	Platform() Platform
	Category() Category
	OpsecLevel() string
	Authors() []string
	References() []string

	// Parameters
	Parameters() []Parameter

	// Execution
	Run(cfg Config) ([]Result, error)
}

// SupportedResourceTypesProvider is an optional interface for modules that scope
// their supported resource types.
type SupportedResourceTypesProvider interface {
	SupportedResourceTypes() []string
}

// SupportedResourceTypes returns the resource types supported by a module, if declared.
func SupportedResourceTypes(m Module) []string {
	if provider, ok := m.(SupportedResourceTypesProvider); ok {
		return provider.SupportedResourceTypes()
	}

	return []string{}
}
