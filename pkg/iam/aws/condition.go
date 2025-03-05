package aws

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/nebula/pkg/types"
)

// ConditionEvalResult represents the outcome of evaluating policy conditions
type ConditionEvalResult string

const (
	// ConditionMatched indicates all conditions were explicitly satisfied
	ConditionMatched ConditionEvalResult = "MATCHED"

	// ConditionFailed indicates at least one condition explicitly failed
	ConditionFailed ConditionEvalResult = "FAILED"

	// ConditionInconclusive indicates evaluation couldn't be completed due to missing context
	ConditionInconclusive ConditionEvalResult = "INCONCLUSIVE"
)

// ConditionEval captures detailed information about condition evaluation
type ConditionEval struct {
	// Overall result of condition evaluation
	Result ConditionEvalResult `json:"result"`

	// The specific conditions from the policy
	Conditions []*types.Condition `json:"conditions,omitempty"`

	// Missing context keys that prevented complete evaluation
	MissingKeys []string `json:"missing_keys,omitempty"`

	// For each condition key, the detailed evaluation result
	KeyResults map[string]KeyEvaluation `json:"key_results,omitempty"`
}

func (c *ConditionEval) Allowed() bool {
	if c.Result == ConditionMatched || c.Result == ConditionInconclusive {
		return true
	}
	return false
}

func (c *ConditionEval) String() string {
	return fmt.Sprintf("ConditionEval{Result: %s, Conditions: %v, MissingKeys: %v, KeyResults: %v}",
		c.Result, c.Conditions, c.MissingKeys, c.KeyResults)
}

// Not defines the behavior of the ! operator for ConditionEval
func (c *ConditionEval) Not() bool {
	// Return true if the condition evaluation failed
	return c.Result == ConditionFailed
}

// KeyEvaluation represents the evaluation of a single condition key
type KeyEvaluation struct {
	Key      string              `json:"key"`
	Operator string              `json:"operator"`
	Values   []string            `json:"values"`
	Result   ConditionEvalResult `json:"result"`
	Context  interface{}         `json:"context_value,omitempty"` // The actual value from the context, if available
}

// SingleCondition represents a single condition rule
type SingleCondition struct {
	Operator string   `json:"operator"`
	Key      string   `json:"key"`
	Values   []string `json:"values"`
}

// evaluateConditions evaluates all conditions in a policy statement
func evaluateConditions(conditions *types.Condition, ctx *RequestContext) *ConditionEval {
	if conditions == nil {
		// No conditions to evaluate, so we match by default
		return &ConditionEval{
			Result: ConditionMatched,
		}
	}

	eval := &ConditionEval{
		Result:      ConditionMatched, // Start optimistic
		MissingKeys: []string{},
		KeyResults:  make(map[string]KeyEvaluation),
	}

	for operator, conditionStatement := range *conditions {
		for key, values := range conditionStatement {
			// Check if the key exists in the context
			exists := doesContextValueExist(key, ctx)
			if !exists && !strings.HasSuffix(operator, "IfExists") && operator != "Null" {
				// Key doesn't exist and we're not using IfExists or Null operator
				eval.MissingKeys = append(eval.MissingKeys, key)

				// Determine if this is a critical key we should default to inconclusive
				if isCriticalConditionKey(key) {
					eval.Result = ConditionInconclusive
					eval.KeyResults[key] = KeyEvaluation{
						Key:      key,
						Operator: operator,
						Values:   values,
						Result:   ConditionInconclusive,
					}
					continue
				}
			}

			// Evaluate the individual condition
			result := evaluateCondition(operator, key, values, ctx)

			keyResult := KeyEvaluation{
				Key:      key,
				Operator: operator,
				Values:   values,
				Result:   ConditionMatched,
				Context:  getContextValue(key, ctx),
			}

			if !result {
				keyResult.Result = ConditionFailed

				// If any condition fails, the overall result is failure
				// (unless we've already marked it inconclusive)
				if eval.Result != ConditionInconclusive {
					eval.Result = ConditionFailed
				}
			}

			eval.KeyResults[key] = keyResult
		}
	}

	return eval
}

// Helper function to identify condition keys that should default to inconclusive
func isCriticalConditionKey(key string) bool {
	criticalKeys := map[string]bool{
		"aws:SourceArn":         true,
		"aws:SourceVpc":         true,
		"aws:SourceVpce":        true,
		"aws:PrincipalOrgID":    true,
		"aws:ResourceOrgID":     true,
		"aws:PrincipalOrgPaths": true,
		"aws:ResourceOrgPaths":  true,
		"aws:SourceAccount":     true,
		"aws:ResourceAccount":   true,
		"aws:ViaAWSService":     true,
		"aws:CalledVia":         true,
		"aws:CalledViaFirst":    true,
		"aws:CalledViaLast":     true,
	}

	return criticalKeys[key]
}

// evaluateCondition evaluates a single condition
func evaluateCondition(operator string, key string, values []string, ctx *RequestContext) bool {
	// Handle IfExists suffix first
	isIfExists := strings.HasSuffix(operator, "IfExists")
	if isIfExists {
		operator = strings.TrimSuffix(operator, "IfExists")
	}

	// Get context value and check existence
	exists, actualValue := findContextKeyValue(key, ctx)

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

func evaluateSetCondition(operator string, key string, values []string, ctx *RequestContext) bool {
	var actualValues []string

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

func doesContextValueExist(key string, ctx *RequestContext) bool {
	exists, _ := findContextKeyValue(key, ctx)
	return exists
}

func getContextValue(key string, ctx *RequestContext) interface{} {
	_, value := findContextKeyValue(key, ctx)
	return value
}

// findContextKeyValue is a helper function that checks if a key exists in the context
// and returns both whether it exists and its value (if it exists)
func findContextKeyValue(key string, ctx *RequestContext) (exists bool, value interface{}) {
	if ctx == nil {
		return false, nil
	}

	// Convert key to lowercase for case-insensitive comparison
	lowerKey := strings.ToLower(key)

	// Handle tag-based keys first as they have special prefix handling
	if strings.HasPrefix(lowerKey, "aws:resourcetag/") {
		tagKey := strings.TrimPrefix(key, "aws:ResourceTag/")
		if ctx.ResourceTags == nil {
			return false, nil
		}
		val, exists := ctx.ResourceTags[tagKey]
		return exists, val
	}

	if strings.HasPrefix(lowerKey, "aws:requesttag/") {
		tagKey := strings.TrimPrefix(key, "aws:RequestTag/")
		if ctx.RequestTags == nil {
			return false, nil
		}
		val, exists := ctx.RequestTags[tagKey]
		return exists, val
	}

	if strings.HasPrefix(lowerKey, "aws:principaltag/") {
		tagKey := strings.TrimPrefix(key, "aws:PrincipalTag/")
		if ctx.PrincipalTags == nil {
			return false, nil
		}
		val, exists := ctx.PrincipalTags[tagKey]
		return exists, val
	}

	// Handle Principal Properties
	switch lowerKey {
	case "aws:principalarn":
		return ctx.PrincipalArn != "", ctx.PrincipalArn
	case "aws:principalaccount":
		return ctx.PrincipalAccount != "", ctx.PrincipalAccount
	case "aws:principalorgid":
		return ctx.PrincipalOrgID != "", ctx.PrincipalOrgID
	case "aws:principalorgpaths":
		return len(ctx.PrincipalOrgPaths) > 0, ctx.PrincipalOrgPaths
	case "aws:principaltype":
		return ctx.PrincipalType != "", ctx.PrincipalType
	case "aws:userid", "aws:username":
		return ctx.PrincipalUsername != "", ctx.PrincipalUsername
	}

	// Handle Role Session Properties
	switch lowerKey {
	case "aws:rolesessionname":
		return ctx.RoleSessionName != "", ctx.RoleSessionName
	case "aws:federatedprovider":
		return ctx.FederatedProvider != "", ctx.FederatedProvider
	case "aws:tokenissuetime":
		return !ctx.TokenIssueTime.IsZero(), ctx.TokenIssueTime
	case "aws:sourceidentity":
		return ctx.SourceIdentity != "", ctx.SourceIdentity
	case "aws:assumedroot":
		return ctx.AssumedRoot != nil, ctx.AssumedRoot
	case "aws:multifactorauthage":
		if ctx.MultiFactorAuthAge != 0 {
			return true, ctx.MultiFactorAuthAge
		}
		return false, nil
	case "aws:multifactorauthpresent":
		return true, ctx.MultiFactorAuthPresent
	case "aws:Ec2InstanceSourceVpc":
		return ctx.Ec2InstanceSourceVpc != "", ctx.Ec2InstanceSourceVpc
	case "aws:Ec2InstanceSourcePrivateIPv4":
		return ctx.Ec2InstanceSourcePrivateIPv4 != "", ctx.Ec2InstanceSourcePrivateIPv4
	case "ec2:RoleDelivery":
		return ctx.ec2_RoleDelivery != "", ctx.ec2_RoleDelivery
	case "ec2:sourceinstancearn":
		return ctx.ec2_SourceInstanceArn != "", ctx.ec2_SourceInstanceArn
	case "glue:roleassumedby":
		return ctx.glue_RoleAssumedBy != "", ctx.glue_RoleAssumedBy
	case "glue:credentialissuingservice":
		return ctx.glue_CredentialIssuingService != "", ctx.glue_CredentialIssuingService
	case "lambda:sourcefunctionarn":
		return ctx.lambda_SourceFunctionArn != "", ctx.lambda_SourceFunctionArn
	case "ssm:sourceinstancearn":
		return ctx.ssm_SourceInstanceArn != "", ctx.ssm_SourceInstanceArn
	case "identitystore:userid":
		return ctx.identitystore_UserId != "", ctx.identitystore_UserId

	}

	// Handle Network Properties
	switch lowerKey {
	case "aws:sourceip":
		return ctx.SourceIP != "", ctx.SourceIP
	case "aws:sourcevpc":
		return ctx.SourceVPC != "", ctx.SourceVPC
	case "aws:sourcevpce":
		return ctx.SourceVPCE != "", ctx.SourceVPCE
	case "aws:vpcsourceip":
		return ctx.VPCSourceIP != "", ctx.VPCSourceIP
	}

	// Handle Resource Properties
	switch lowerKey {
	case "aws:resourceaccount":
		return ctx.ResourceAccount != "", ctx.ResourceAccount
	case "aws:resourceorgid":
		return ctx.ResourceOrgID != "", ctx.ResourceOrgID
	case "aws:resourceorgpaths":
		return len(ctx.ResourceOrgPaths) > 0, ctx.ResourceOrgPaths
	}

	// Handle Request Properties
	switch lowerKey {
	case "aws:currenttime":
		return !ctx.CurrentTime.IsZero(), ctx.CurrentTime
	case "aws:requestedregion":
		return ctx.RequestedRegion != "", ctx.RequestedRegion
	case "aws:securetransport":
		return ctx.SecureTransport != nil, ctx.SecureTransport
	case "aws:useragent":
		return ctx.UserAgent != "", ctx.UserAgent
	case "aws:referer":
		return ctx.Referer != "", ctx.Referer
	}

	// Handle Cross-service Properties
	switch lowerKey {
	case "aws:viaawsservice":
		return ctx.ViaAWSService != nil, ctx.ViaAWSService
	case "aws:calledvia":
		return len(ctx.CalledVia) > 0, ctx.CalledVia
	case "aws:calledviafirst":
		if len(ctx.CalledVia) > 0 {
			return true, ctx.CalledVia[0]
		}
		return false, nil
	case "aws:calledvialast":
		if len(ctx.CalledVia) > 0 {
			return true, ctx.CalledVia[len(ctx.CalledVia)-1]
		}
		return false, nil
	case "aws:sourcearn":
		return ctx.SourceArn != "", ctx.SourceArn
	case "aws:sourceaccount":
		return ctx.SourceAccount != "", ctx.SourceAccount
	case "aws:sourceorgid":
		return ctx.SourceOrgID != "", ctx.SourceOrgID
	case "aws:sourceorgpaths":
		return len(ctx.SourceOrgPaths) > 0, ctx.SourceOrgPaths
	}

	// Special handling for TagKeys - aggregate all tag keys from all tag maps
	if lowerKey == "aws:tagkeys" {
		var keys []string
		for k := range ctx.PrincipalTags {
			keys = append(keys, k)
		}
		for k := range ctx.ResourceTags {
			keys = append(keys, k)
		}
		for k := range ctx.RequestTags {
			keys = append(keys, k)
		}
		return len(keys) > 0, keys
	}

	// Check the request parameters for any other keys not handled above
	if ctx.RequestParameters != nil {
		if val, ok := ctx.RequestParameters[key]; ok {
			return true, val
		}
	}

	return false, nil
}

// getTagKeys is a helper function to get all tag keys from all tag maps
func getTagKeys(ctx *RequestContext) []string {
	// Use a map to deduplicate keys
	keyMap := make(map[string]bool)

	for k := range ctx.PrincipalTags {
		keyMap[k] = true
	}
	for k := range ctx.ResourceTags {
		keyMap[k] = true
	}
	for k := range ctx.RequestTags {
		keyMap[k] = true
	}

	// Convert to slice
	keys := make([]string, 0, len(keyMap))
	for k := range keyMap {
		keys = append(keys, k)
	}

	return keys
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
	// Convert string value to bool
	expected := values[0] == "true"

	switch v := actualValue.(type) {
	case *bool:
		if v == nil {
			return false
		}
		return *v == expected
	case bool:
		return v == expected
	default:
		return false
	}
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
