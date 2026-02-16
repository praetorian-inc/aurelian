package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestFlattenJSON_SimpleMap tests flattening a simple map with no nesting
func TestFlattenJSON_SimpleMap(t *testing.T) {
	input := map[string]interface{}{
		"key": "value",
	}

	result := FlattenJSON(input)

	assert.Equal(t, "value", result["key"])
	assert.Len(t, result, 1)
}

// TestFlattenJSON_NestedMap tests flattening a single-level nested map
func TestFlattenJSON_NestedMap(t *testing.T) {
	input := map[string]interface{}{
		"a": map[string]interface{}{
			"b": "c",
		},
	}

	result := FlattenJSON(input)

	assert.Equal(t, "c", result["a.b"])
	assert.Len(t, result, 1)
}

// TestFlattenJSON_DeeplyNested tests flattening a deeply nested structure
func TestFlattenJSON_DeeplyNested(t *testing.T) {
	input := map[string]interface{}{
		"a": map[string]interface{}{
			"b": map[string]interface{}{
				"c": "d",
			},
		},
	}

	result := FlattenJSON(input)

	assert.Equal(t, "d", result["a.b.c"])
	assert.Len(t, result, 1)
}

// TestFlattenJSON_Array tests that arrays are converted to JSON strings
func TestFlattenJSON_Array(t *testing.T) {
	input := map[string]interface{}{
		"tags": []interface{}{1, 2, 3},
	}

	result := FlattenJSON(input)

	// Arrays should be JSON-encoded as strings
	assert.Equal(t, "[1,2,3]", result["tags"])
	assert.Len(t, result, 1)
}

// TestFlattenJSON_MixedTypes tests a map with various types
func TestFlattenJSON_MixedTypes(t *testing.T) {
	input := map[string]interface{}{
		"string":  "value",
		"int":     42,
		"bool":    true,
		"nested": map[string]interface{}{
			"field": "nested_value",
		},
		"array": []interface{}{"a", "b"},
	}

	result := FlattenJSON(input)

	assert.Equal(t, "value", result["string"])
	assert.Equal(t, 42, result["int"])
	assert.Equal(t, true, result["bool"])
	assert.Equal(t, "nested_value", result["nested.field"])
	assert.Equal(t, `["a","b"]`, result["array"])
	assert.Len(t, result, 5)
}

// TestFlattenJSON_EmptyMap tests that an empty map returns an empty map
func TestFlattenJSON_EmptyMap(t *testing.T) {
	input := map[string]interface{}{}

	result := FlattenJSON(input)

	assert.NotNil(t, result)
	assert.Len(t, result, 0)
}

// TestFlattenJSON_NilInput tests that nil input is handled gracefully
func TestFlattenJSON_NilInput(t *testing.T) {
	result := FlattenJSON(nil)

	assert.NotNil(t, result)
	assert.Len(t, result, 0)
}

// TestConvertAndFlatten_Struct tests converting a Go struct to flattened map
func TestConvertAndFlatten_Struct(t *testing.T) {
	type TestStruct struct {
		Name  string `json:"name"`
		Age   int    `json:"age"`
		Email string `json:"email"`
	}

	input := TestStruct{
		Name:  "John",
		Age:   30,
		Email: "john@example.com",
	}

	result, err := ConvertAndFlatten(input)

	assert.NoError(t, err)
	assert.Equal(t, "John", result["name"])
	assert.Equal(t, float64(30), result["age"]) // JSON unmarshals numbers as float64
	assert.Equal(t, "john@example.com", result["email"])
	assert.Len(t, result, 3)
}

// TestUnescapeJSONString tests various escape sequence handling
func TestUnescapeJSONString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "quoted string",
			input:    `"hello"`,
			expected: "hello",
		},
		{
			name:     "escaped quotes",
			input:    `"say \"hello\""`,
			expected: `say "hello"`,
		},
		{
			name:     "escaped backslash",
			input:    `"path\\to\\file"`,
			expected: `path\to\file`,
		},
		{
			name:     "newline",
			input:    `"line1\nline2"`,
			expected: "line1\nline2",
		},
		{
			name:     "tab",
			input:    `"col1\tcol2"`,
			expected: "col1\tcol2",
		},
		{
			name:     "no quotes",
			input:    "plain",
			expected: "plain",
		},
		{
			name:     "empty string",
			input:    `""`,
			expected: "",
		},
		{
			name:     "mixed escapes",
			input:    `"a\"b\\c\nd"`,
			expected: "a\"b\\c\nd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := UnescapeJSONString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
