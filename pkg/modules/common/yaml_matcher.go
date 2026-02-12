package common

import (
	"regexp"
	"strings"
)

// EvaluateCondition checks if a single match condition is true for the given properties.
func EvaluateCondition(condition MatchCondition, properties map[string]any) bool {
	// Get property value (nested paths not supported yet - Phase 2 enhancement)
	value, exists := properties[condition.Field]

	// Exists operator
	if condition.Exists != nil {
		return exists == *condition.Exists
	}

	// All other operators require the property to exist
	if !exists {
		return false
	}

	// Equals operator
	if condition.Equals != nil {
		return compareValues(value, condition.Equals)
	}

	// NotEquals operator
	if condition.NotEquals != nil {
		return !compareValues(value, condition.NotEquals)
	}

	// Contains operator
	if condition.Contains != "" {
		return containsValue(value, condition.Contains)
	}

	// Regex operator
	if condition.Regex != "" {
		re, err := regexp.Compile(condition.Regex)
		if err != nil {
			return false // Invalid regex = no match
		}
		if str, ok := value.(string); ok {
			return re.MatchString(str)
		}
		return false
	}

	// GreaterThan operator
	if condition.GreaterThan != 0 {
		return compareNumeric(value, condition.GreaterThan, ">")
	}

	// LessThan operator
	if condition.LessThan != 0 {
		return compareNumeric(value, condition.LessThan, "<")
	}

	// No operator set - invalid condition
	return false
}

// MatchAll checks if ALL conditions are true (implicit AND).
func MatchAll(conditions []MatchCondition, properties map[string]any) bool {
	for _, cond := range conditions {
		if !EvaluateCondition(cond, properties) {
			return false
		}
	}
	return true
}

// compareValues compares two values for equality (handles type conversions).
func compareValues(actual, expected any) bool {
	// Direct equality
	if actual == expected {
		return true
	}

	// String comparison (case-sensitive)
	actualStr, actualIsStr := actual.(string)
	expectedStr, expectedIsStr := expected.(string)
	if actualIsStr && expectedIsStr {
		return actualStr == expectedStr
	}

	// Numeric comparison (handle int/float conversions)
	actualNum, actualIsNum := toFloat64(actual)
	expectedNum, expectedIsNum := toFloat64(expected)
	if actualIsNum && expectedIsNum {
		return actualNum == expectedNum
	}

	return false
}

// containsValue checks if a value contains a substring or list element.
func containsValue(value any, search string) bool {
	// String substring match
	if str, ok := value.(string); ok {
		return strings.Contains(str, search)
	}

	// List membership ([]string or []any)
	if slice, ok := value.([]string); ok {
		for _, item := range slice {
			if item == search {
				return true
			}
		}
	}
	if slice, ok := value.([]any); ok {
		for _, item := range slice {
			if str, ok := item.(string); ok && str == search {
				return true
			}
		}
	}

	return false
}

// compareNumeric handles numeric comparisons with type conversion.
func compareNumeric(value any, threshold float64, operator string) bool {
	num, ok := toFloat64(value)
	if !ok {
		return false
	}

	switch operator {
	case ">":
		return num > threshold
	case "<":
		return num < threshold
	default:
		return false
	}
}

// toFloat64 converts int/float values to float64 for comparison.
func toFloat64(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case int32:
		return float64(v), true
	default:
		return 0, false
	}
}
