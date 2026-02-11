package plugin

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Group 1: EffectiveValue (3 tests)
// ============================================================================

func TestEffectiveValue_ExplicitValue(t *testing.T) {
	p := Parameter{
		Name:    "host",
		Value:   "hello",
		IsSet:   true,
		Default: "default",
	}

	result := p.EffectiveValue()
	assert.Equal(t, "hello", result)
}

func TestEffectiveValue_DefaultFallback(t *testing.T) {
	p := Parameter{
		Name:    "host",
		Default: "fallback",
		IsSet:   false,
	}

	result := p.EffectiveValue()
	assert.Equal(t, "fallback", result)
}

func TestEffectiveValue_NilWhenUnset(t *testing.T) {
	p := Parameter{
		Name:    "host",
		IsSet:   false,
		Default: nil,
	}

	result := p.EffectiveValue()
	assert.Nil(t, result)
}

// ============================================================================
// Group 2: Typed Accessors (8 tests) - table-driven
// ============================================================================

func TestString_ExplicitValue(t *testing.T) {
	ps := NewParameters(
		Parameter{Name: "host", Type: "string"},
	)
	ps.Set("host", "example.com")

	result := ps.String("host")
	assert.Equal(t, "example.com", result)
}

func TestString_Default(t *testing.T) {
	ps := NewParameters(
		Parameter{Name: "host", Type: "string", Default: "localhost"},
	)

	result := ps.String("host")
	assert.Equal(t, "localhost", result)
}

func TestString_MissingParam(t *testing.T) {
	ps := NewParameters()

	result := ps.String("nonexistent")
	assert.Equal(t, "", result)
}

func TestString_TypeMismatch(t *testing.T) {
	ps := NewParameters(
		Parameter{Name: "count", Type: "int"},
	)
	ps.Set("count", 42)

	result := ps.String("count")
	assert.Equal(t, "", result, "type assertion should fail silently, returning zero value")
}

func TestInt_ExplicitValue(t *testing.T) {
	ps := NewParameters(
		Parameter{Name: "port", Type: "int"},
	)
	ps.Set("port", 8080)

	result := ps.Int("port")
	assert.Equal(t, 8080, result)
}

func TestBool_ExplicitValue(t *testing.T) {
	ps := NewParameters(
		Parameter{Name: "verbose", Type: "bool"},
	)
	ps.Set("verbose", true)

	result := ps.Bool("verbose")
	assert.True(t, result)
}

func TestBool_DefaultFalse(t *testing.T) {
	ps := NewParameters(
		Parameter{Name: "verbose", Type: "bool"},
	)

	result := ps.Bool("verbose")
	assert.False(t, result, "bool should return false when not set and no default")
}

func TestStringSlice_ExplicitValue(t *testing.T) {
	ps := NewParameters(
		Parameter{Name: "tags", Type: "[]string"},
	)
	ps.Set("tags", []string{"a", "b"})

	result := ps.StringSlice("tags")
	assert.Equal(t, []string{"a", "b"}, result)
}

// ============================================================================
// Group 3: Validate (6 tests) - table-driven
// ============================================================================

func TestValidate_RequiredMissing(t *testing.T) {
	ps := NewParameters(
		Parameter{Name: "apikey", Type: "string", Required: true},
	)

	err := ps.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required parameter")
	assert.Contains(t, err.Error(), "apikey")
}

func TestValidate_RequiredWithDefault(t *testing.T) {
	ps := NewParameters(
		Parameter{Name: "apikey", Type: "string", Required: true, Default: "default-key"},
	)

	err := ps.Validate()
	assert.NoError(t, err)
}

func TestValidate_PatternMatch(t *testing.T) {
	pattern := regexp.MustCompile(`^[a-z]+$`)
	ps := NewParameters(
		Parameter{Name: "name", Type: "string", Pattern: pattern},
	)
	ps.Set("name", "abc")

	err := ps.Validate()
	assert.NoError(t, err)
}

func TestValidate_PatternMismatch(t *testing.T) {
	pattern := regexp.MustCompile(`^[a-z]+$`)
	ps := NewParameters(
		Parameter{Name: "name", Type: "string", Pattern: pattern},
	)
	ps.Set("name", "ABC123")

	err := ps.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match pattern")
}

func TestValidate_EnumValid(t *testing.T) {
	ps := NewParameters(
		Parameter{Name: "severity", Type: "string", Enum: []string{"low", "medium", "high"}},
	)
	ps.Set("severity", "Medium") // Case-insensitive

	err := ps.Validate()
	assert.NoError(t, err)
}

func TestValidate_EnumInvalid(t *testing.T) {
	ps := NewParameters(
		Parameter{Name: "severity", Type: "string", Enum: []string{"low", "medium", "high"}},
	)
	ps.Set("severity", "critical")

	err := ps.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not one of allowed values")
}

// ============================================================================
// Group 4: Group Constraints (3 tests)
// ============================================================================

func TestValidate_RequiredTogetherPartialSet(t *testing.T) {
	ps := NewParameters(
		Parameter{Name: "user", Type: "string"},
		Parameter{Name: "pass", Type: "string"},
	)
	ps = ps.RequiredTogether("user", "pass")
	ps.Set("user", "admin") // Only user set, not pass

	err := ps.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be set together")
}

func TestValidate_RequiredTogetherAllSet(t *testing.T) {
	ps := NewParameters(
		Parameter{Name: "user", Type: "string"},
		Parameter{Name: "pass", Type: "string"},
	)
	ps = ps.RequiredTogether("user", "pass")
	ps.Set("user", "admin")
	ps.Set("pass", "secret")

	err := ps.Validate()
	assert.NoError(t, err)
}

func TestValidate_MutuallyExclusiveViolation(t *testing.T) {
	ps := NewParameters(
		Parameter{Name: "json", Type: "bool"},
		Parameter{Name: "csv", Type: "bool"},
	)
	ps = ps.MutuallyExclusive("json", "csv")
	ps.Set("json", true)
	ps.Set("csv", true) // Both set

	err := ps.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

// ============================================================================
// Group 5: Set/IsSet and ToArgs (3 tests)
// ============================================================================

func TestSetAndIsSet(t *testing.T) {
	ps := NewParameters(
		Parameter{Name: "host", Type: "string"},
	)

	// Before Set
	assert.False(t, ps.IsSet("host"))

	// After Set
	ps.Set("host", "example.com")
	assert.True(t, ps.IsSet("host"))
}

func TestIsSet_NonexistentParam(t *testing.T) {
	ps := NewParameters()

	result := ps.IsSet("ghost")
	assert.False(t, result)
}

func TestToArgs(t *testing.T) {
	ps := NewParameters(
		Parameter{Name: "host", Type: "string"},
		Parameter{Name: "port", Type: "int", Default: 8080},
	)
	ps.Set("host", "example.com")
	// port not set, but has default

	args := ps.ToArgs()

	assert.Equal(t, 2, len(args), "should have both host (set) and port (default)")
	assert.Equal(t, "example.com", args["host"])
	assert.Equal(t, 8080, args["port"])
}
