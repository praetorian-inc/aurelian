package iamadmin

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

const administratorAccessPolicyARN = "arn:aws:iam::aws:policy/AdministratorAccess"

func hasAdministratorAccessPolicy(policies []types.AttachedPolicy) bool {
	for _, policy := range policies {
		matchesAdministratorAccess := aws.ToString(policy.PolicyArn) == administratorAccessPolicyARN
		if matchesAdministratorAccess {
			return true
		}
	}

	return false
}

func policyDocumentHasAdminWildcardStatement(raw string) bool {
	decodedRaw := decodePolicyDocument(raw)
	if decodedRaw == "" {
		return false
	}

	var policy map[string]any
	if err := json.Unmarshal([]byte(decodedRaw), &policy); err != nil {
		return false
	}

	statementValue, hasStatement := policy["Statement"]
	if !hasStatement {
		return false
	}

	return statementListHasAdminWildcard(statementValue)
}

func decodePolicyDocument(raw string) string {
	if raw == "" {
		return ""
	}

	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		return raw
	}

	return decoded
}

func statementListHasAdminWildcard(statementValue any) bool {
	statements, ok := normalizeStatements(statementValue)
	if !ok {
		return false
	}

	for _, statement := range statements {
		isAdministratorStatement := statementIsAdminWildcard(statement)
		if isAdministratorStatement {
			return true
		}
	}

	return false
}

func normalizeStatements(statementValue any) ([]map[string]any, bool) {
	singleStatement, isSingleStatement := statementValue.(map[string]any)
	if isSingleStatement {
		return []map[string]any{singleStatement}, true
	}

	statementList, isStatementList := statementValue.([]any)
	if !isStatementList {
		return nil, false
	}

	result := make([]map[string]any, 0, len(statementList))
	for _, entry := range statementList {
		statement, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		result = append(result, statement)
	}

	return result, true
}

func statementIsAdminWildcard(statement map[string]any) bool {
	effect, _ := statement["Effect"].(string)
	isAllowEffect := strings.EqualFold(effect, "Allow")
	if !isAllowEffect {
		return false
	}

	actionHasWildcard := valueContainsWildcard(statement["Action"])
	if !actionHasWildcard {
		return false
	}

	resourceHasWildcard := valueContainsWildcard(statement["Resource"])
	if !resourceHasWildcard {
		return false
	}

	return true
}

func valueContainsWildcard(value any) bool {
	stringValue, isString := value.(string)
	if isString {
		return strings.TrimSpace(stringValue) == "*"
	}

	listValue, isList := value.([]any)
	if !isList {
		return false
	}

	for _, entry := range listValue {
		entryString, ok := entry.(string)
		if !ok {
			continue
		}

		hasWildcard := strings.TrimSpace(entryString) == "*"
		if hasWildcard {
			return true
		}
	}

	return false
}
