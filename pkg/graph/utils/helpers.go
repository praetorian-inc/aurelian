package utils

import (
	"encoding/json"
	"strings"
)

// FlattenJSON converts nested JSON-like structures to flat map with dot-notation keys.
// Nested maps become "a.b" keys, arrays are JSON-encoded as strings.
// Returns empty map for nil input.
func FlattenJSON(data interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	if data == nil {
		return result
	}
	flatten("", data, result)
	return result
}

// flatten is the recursive helper for FlattenJSON.
// prefix accumulates the dot-notation key path.
func flatten(prefix string, data interface{}, result map[string]interface{}) {
	switch v := data.(type) {
	case map[string]interface{}:
		// Recurse into nested maps
		for key, val := range v {
			newKey := key
			if prefix != "" {
				newKey = prefix + "." + key
			}
			flatten(newKey, val, result)
		}
	case []interface{}:
		// Arrays -> JSON string representation
		jsonBytes, _ := json.Marshal(v)
		result[prefix] = string(jsonBytes)
	default:
		// Primitive values pass through unchanged
		result[prefix] = v
	}
}

// ConvertAndFlatten marshals a Go struct to JSON, unmarshals to interface{},
// then flattens it using FlattenJSON.
func ConvertAndFlatten(obj interface{}) (map[string]interface{}, error) {
	// Marshal to JSON bytes
	jsonBytes, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}

	// Unmarshal to interface{} (generic map structure)
	var data interface{}
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		return nil, err
	}

	// Flatten the result
	return FlattenJSON(data), nil
}

// UnescapeJSONString removes JSON escaping from a string.
// Trims surrounding quotes and unescapes \", \\, \n, \t.
func UnescapeJSONString(s string) string {
	// Remove surrounding quotes if present (only first and last character)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}

	// Unescape JSON sequences in correct order
	// Process \\ first with placeholder to avoid double-processing
	s = strings.ReplaceAll(s, `\\`, "\uFFFF")
	s = strings.ReplaceAll(s, `\"`, `"`)
	s = strings.ReplaceAll(s, `\n`, "\n")
	s = strings.ReplaceAll(s, `\t`, "\t")
	s = strings.ReplaceAll(s, "\uFFFF", `\`)

	return s
}
