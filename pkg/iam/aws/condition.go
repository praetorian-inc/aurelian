package aws

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/nebula/pkg/types"
)

func evaluateConditions(conditions *types.Condition, ctx *RequestContext) bool {
	for operator, keyValues := range *conditions {
		for key, values := range keyValues {
			if !evaluateCondition(operator, key, values, ctx) {
				return false
			}
		}
	}
	return true
}

func evaluateCondition(operator string, key string, values []string, ctx *RequestContext) bool {
	// Handle IfExists suffix first
	isIfExists := strings.HasSuffix(operator, "IfExists")
	if isIfExists {
		operator = strings.TrimSuffix(operator, "IfExists")
	}

	// Get context value and check existence
	actualValue := getContextValue(key, ctx)
	exists := doesContextValueExist(key, ctx)

	// Handle Null operator
	if operator == "Null" {
		wantNull := values[0] == "true"
		return wantNull == !exists
	}

	// Handle IfExists - if key doesn't exist, return true
	if !exists && isIfExists {
		return true
	}

	// Handle special set operators
	if strings.HasPrefix(operator, "ForAllValues:") || strings.HasPrefix(operator, "ForAnyValue:") {
		return evaluateSetCondition(operator, key, values, ctx)
	}

	// Handle non-existent values for non-IfExists operators
	if actualValue == nil {
		return false
	}

	baseOperator := strings.TrimPrefix(strings.TrimPrefix(operator, "ForAllValues:"), "ForAnyValue:")

	switch {
	case strings.HasPrefix(baseOperator, "String"):
		return evaluateStringCondition(baseOperator, values, actualValue)
	case strings.HasPrefix(baseOperator, "Numeric"):
		parsed, converted := toFloat64(actualValue)
		if !converted {
			return false
		}
		return evaluateNumericCondition(baseOperator, values, parsed)
	case strings.HasPrefix(baseOperator, "Date"):
		return evaluateDateCondition(baseOperator, values, actualValue)
	case baseOperator == "Bool":
		return evaluateBoolCondition(values, actualValue)
	case strings.HasPrefix(baseOperator, "IpAddress") || baseOperator == "NotIpAddress":
		return evaluateIpAddressCondition(baseOperator == "IpAddress", values, actualValue)
	case strings.HasPrefix(baseOperator, "Arn"):
		return evaluateArnCondition(baseOperator, values, actualValue)
	}
	return false
}

// New helper function to check if a context value exists
func doesContextValueExist(key string, ctx *RequestContext) bool {
	if ctx == nil {
		return false
	}

	// Handle tag-based keys
	if strings.HasPrefix(key, "aws:ResourceTag/") {
		tagKey := strings.TrimPrefix(key, "aws:ResourceTag/")
		if ctx.ResourceTags == nil {
			return false
		}
		_, exists := ctx.ResourceTags[tagKey]
		return exists
	}

	if strings.HasPrefix(key, "aws:RequestTag/") {
		tagKey := strings.TrimPrefix(key, "aws:RequestTag/")
		if ctx.RequestTags == nil {
			return false
		}
		_, exists := ctx.RequestTags[tagKey]
		return exists
	}

	if strings.HasPrefix(key, "aws:PrincipalTag/") {
		tagKey := strings.TrimPrefix(key, "aws:PrincipalTag/")
		if ctx.ResourceTags == nil {
			return false
		}
		_, exists := ctx.ResourceTags[tagKey]
		return exists
	}

	// Handle PrincipalOrgPaths specially
	if key == "aws:PrincipalOrgPaths" {
		_, exists := ctx.RequestParameters["PrincipalOrgPaths"]
		return exists
	}

	if key == "aws:PrincipalOrgID" {
		return true
	}

	// Check request parameters
	if ctx.RequestParameters != nil {
		if _, ok := ctx.RequestParameters[key]; ok {
			return true
		}
	}

	// Check standard context keys
	switch key {
	case "aws:CurrentTime":
		return !ctx.CurrentTime.IsZero()
	case "aws:SourceIp":
		return ctx.SourceIp != ""
	case "aws:PrincipalArn":
		return ctx.PrincipalArn != ""
	case "aws:UserAgent":
		return ctx.UserAgent != ""
	}

	return false
}

func evaluateSetCondition(operator string, key string, values []string, ctx *RequestContext) bool {
	var actualValues []string

	// Handle PrincipalOrgPaths specially
	if key == "aws:PrincipalOrgPaths" {
		if val, ok := ctx.RequestParameters["PrincipalOrgPaths"]; ok {
			actualValues = []string{val}
		}
	} else {
		// Get normal context value
		actualValue := getContextValue(key, ctx)
		if actualValue == nil {
			return false
		}

		switch v := actualValue.(type) {
		case []string:
			actualValues = v
		case map[string]string:
			for k := range v {
				actualValues = append(actualValues, k)
			}
		case string:
			actualValues = []string{v}
		default:
			return false
		}
	}

	baseOperator := ""
	if strings.HasPrefix(operator, "ForAllValues:") {
		if len(actualValues) == 0 {
			return true
		}
		baseOperator = strings.TrimPrefix(operator, "ForAllValues:")
		for _, actualVal := range actualValues {
			matched := false
			for _, expected := range values {
				if evaluateStringCondition(baseOperator, []string{expected}, actualVal) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
		return true
	}

	if strings.HasPrefix(operator, "ForAnyValue:") {
		baseOperator = strings.TrimPrefix(operator, "ForAnyValue:")
		for _, actualVal := range actualValues {
			for _, expected := range values {
				if evaluateStringCondition(baseOperator, []string{expected}, actualVal) {
					return true
				}
			}
		}
	}

	return false
}

func getContextValue(key string, ctx *RequestContext) interface{} {
	if ctx == nil {
		return nil
	}

	// Handle tag-based keys
	if strings.HasPrefix(key, "aws:ResourceTag/") {
		tagKey := strings.TrimPrefix(key, "aws:ResourceTag/")
		if ctx.ResourceTags == nil {
			return nil
		}
		return ctx.ResourceTags[tagKey]
	}

	if strings.HasPrefix(key, "aws:RequestTag/") {
		tagKey := strings.TrimPrefix(key, "aws:RequestTag/")
		if ctx.RequestTags == nil {
			return nil
		}
		return ctx.RequestTags[tagKey]
	}

	if strings.HasPrefix(key, "aws:PrincipalTag/") {
		tagKey := strings.TrimPrefix(key, "aws:PrincipalTag/")
		if ctx.ResourceTags == nil {
			return nil
		}
		return ctx.ResourceTags[tagKey]
	}

	if strings.EqualFold(key, "aws:PrincipalOrgId") {
		return ctx.PrincipalOrgId
	}

	// Special handling for TagKeys
	if key == "aws:TagKeys" {
		return getTagKeys(ctx)
	}

	// Handle request parameters first as they can override standard keys
	if ctx.RequestParameters != nil {
		if val, ok := ctx.RequestParameters[key]; ok {
			return val
		}
	}

	// Handle standard AWS context keys
	switch key {
	case "aws:CurrentTime":
		return ctx.CurrentTime
	case "aws:username":
		return ctx.RequestParameters["aws:username"]
	case "aws:SourceIp":
		return ctx.SourceIp
	case "aws:PrincipalArn":
		return ctx.PrincipalArn
	case "aws:UserAgent":
		return ctx.UserAgent
	case "aws:SecureTransport":
		return ctx.SecureTransport
	case "aws:MultiFactorAuthAge":
		if val, ok := ctx.RequestParameters["MultiFactorAuthAge"]; ok {
			return val
		}
	}

	return nil
}

func evaluateStringCondition(operator string, values []string, actualValue interface{}) bool {
	actual := fmt.Sprintf("%v", actualValue) // Convert any type to string

	switch operator {
	case "StringEquals":
		for _, v := range values {
			if actual == v {
				return true
			}
		}
	case "StringNotEquals":
		for _, v := range values {
			if actual == v {
				return false
			}
		}
		return true
	case "StringEqualsIgnoreCase":
		actualLower := strings.ToLower(actual)
		for _, v := range values {
			if actualLower == strings.ToLower(v) {
				return true
			}
		}
	case "StringLike":
		for _, v := range values {
			if matchesPattern(v, actual) {
				return true
			}
		}
	case "StringNotLike":
		for _, v := range values {
			if matchesPattern(v, actual) {
				return false
			}
		}
		return true
	}
	return false
}

func evaluateNumericCondition(operator string, values []string, actualValue float64) bool {
	for _, v := range values {
		expected, err := strconv.ParseFloat(v, 64)
		if err != nil {
			continue
		}

		switch operator {
		case "NumericEquals":
			if actualValue == expected {
				return true
			}
		case "NumericNotEquals":
			if actualValue == expected {
				return false // Return false if we find a match
			}
		case "NumericLessThan":
			if actualValue < expected {
				return true
			}
		case "NumericLessThanEquals":
			if actualValue <= expected {
				return true
			}
		case "NumericGreaterThan":
			if actualValue > expected {
				return true
			}
		case "NumericGreaterThanEquals":
			if actualValue >= expected {
				return true
			}
		}
	}

	// After checking all values:
	// - For NumericNotEquals, if we get here no matches were found, so return true
	// - For all other operators, if we get here no matches were found, so return false
	return operator == "NumericNotEquals"
}

func evaluateDateCondition(operator string, values []string, actualValue interface{}) bool {
	actual, ok := actualValue.(time.Time)
	if !ok {
		return false
	}

	for _, v := range values {
		expected, err := time.Parse(time.RFC3339, v)
		if err != nil {
			continue
		}

		switch operator {
		case "DateEquals":
			if actual.Equal(expected) {
				return true
			}
		case "DateNotEquals":
			if actual.Equal(expected) {
				return false
			}
		case "DateLessThan":
			if actual.Before(expected) {
				return true
			}
		case "DateLessThanEquals":
			if actual.Before(expected) || actual.Equal(expected) {
				return true
			}
		case "DateGreaterThan":
			if actual.After(expected) {
				return true
			}
		case "DateGreaterThanEquals":
			if actual.After(expected) || actual.Equal(expected) {
				return true
			}
		}
	}

	return operator == "DateNotEquals"
}

func evaluateBoolCondition(values []string, actualValue interface{}) bool {
	actual, ok := actualValue.(bool)
	if !ok {
		return false
	}

	// Convert string value to bool
	expected := values[0] == "true"
	return actual == expected
}

func evaluateArnCondition(operator string, values []string, actualValue interface{}) bool {
	actual, ok := actualValue.(string)
	if !ok {
		return false
	}

	for _, v := range values {
		matches := matchesPattern(v, actual)

		switch operator {
		case "ArnEquals", "ArnLike":
			if matches {
				return true
			}
		case "ArnNotEquals", "ArnNotLike":
			if matches {
				return false
			}
		}
	}

	if operator == "ArnNotEquals" || operator == "ArnNotLike" {
		return true
	}
	return false
}

func evaluateIpAddressCondition(isPositive bool, values []string, actualValue interface{}) bool {
	actual := fmt.Sprintf("%v", actualValue)
	actualIP := net.ParseIP(actual)
	if actualIP == nil {
		return false
	}

	for _, v := range values {
		_, ipNet, err := net.ParseCIDR(v)
		if err != nil {
			// Try as single IP
			if ip := net.ParseIP(v); ip != nil {
				if actualIP.Equal(ip) == isPositive {
					return true
				}
				continue
			}
			continue
		}

		if ipNet.Contains(actualIP) == isPositive {
			return true
		}
	}

	return !isPositive
}

func getTagKeys(ctx *RequestContext) []string {
	var keys []string
	// Get keys from all tag maps
	for k := range ctx.ResourceTags {
		keys = append(keys, k)
	}
	for k := range ctx.RequestTags {
		keys = append(keys, k)
	}
	for k := range ctx.ResourceTags {
		keys = append(keys, k)
	}
	return keys
}

func toFloat64(v interface{}) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case float32:
		return float64(t), true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case string:
		if f, err := strconv.ParseFloat(t, 64); err == nil {
			return f, true
		}
	}
	return 0, false
}
