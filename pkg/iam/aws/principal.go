package aws

import (
	"reflect"
	"strings"

	"github.com/praetorian-inc/nebula/pkg/types"
)

type PrincipalType string

// AWS principal types
const (
	PrincipalTypeAWS            PrincipalType = "AWS"
	PrincipalTypeService        PrincipalType = "Service"
	PrincipalTypeFederated      PrincipalType = "Federated"
	PrincipalTypeCanonicalUser  PrincipalType = "CanonicalUser"
	PrincipalTypeUser           PrincipalType = "User"
	PrincipalTypeRole           PrincipalType = "Role"
	PrincipalTypeRoleSession    PrincipalType = "RoleSession"
	PrincipalTypeFederatedUser  PrincipalType = "FederatedUser"
	PrincipalTypeServiceAccount PrincipalType = "ServiceAccount"
	PrincipalTypeRoot           PrincipalType = "Root"
	PrincipalTypeUnknown        PrincipalType = "Unknown"
)

func ExtractPrincipalsFromPrincipalPolicyList(policyList []types.PrincipalPL) ([]types.Principal, error) {
	principals := make([]types.Principal, 0)
	for _, policy := range policyList {
		extracted, err := ExtractPrincipals(&policy.PolicyDocument)
		if err != nil {
			return nil, err
		}
		principals = append(principals, extracted...)
	}

	return principals, nil
}

// ExtractPrincipals parses a policy document and returns all referenced principals
func ExtractPrincipals(policy *types.Policy) ([]types.Principal, error) {

	principals := make([]types.Principal, 0)

	// Process each statement
	for _, statement := range *policy.Statement {
		// Extract from Principal element
		if statement.Principal != nil {
			extractedPrincipals := extractPrincipalElement(statement.Principal)
			principals = append(principals, extractedPrincipals...)
		}

		// Extract from NotPrincipal element
		if statement.NotPrincipal != nil {
			extractedPrincipals := extractPrincipalElement(statement.NotPrincipal)
			principals = append(principals, extractedPrincipals...)
		}

		// Extract from Resource element
		if statement.Resource != nil {
			extractedPrincipals := extractPrincipalFromResource(statement.Resource)
			principals = append(principals, extractedPrincipals...)
		}

		// Extract from NotResource element
		if statement.NotResource != nil {
			extractedPrincipals := extractPrincipalFromResource(statement.NotResource)
			principals = append(principals, extractedPrincipals...)
		}

		// Extract from Condition element
		if statement.Condition != nil {
			extractedPrincipals := extractPrincipalFromConditions(statement.Condition)
			principals = append(principals, extractedPrincipals...)
		}
	}

	return UniquePrincipals(principals), nil
}

// extractPrincipalElement handles the different formats of Principal/NotPrincipal elements
func extractPrincipalElement(principalData *types.Principal) []types.Principal {
	principals := make([]types.Principal, 0)

	if principalData.AWS != nil {
		principals = append(principals, types.Principal{
			AWS: principalData.AWS,
		})
	}

	if principalData.Service != nil {
		principals = append(principals, types.Principal{
			Service: principalData.Service,
		})
	}

	if principalData.Federated != nil {
		principals = append(principals, types.Principal{
			Federated: principalData.Federated,
		})
	}

	if principalData.CanonicalUser != nil {
		principals = append(principals, types.Principal{
			CanonicalUser: principalData.CanonicalUser,
		})
	}

	return principals
}

// extractPrincipalFromConditions extracts principals from relevant condition keys
func extractPrincipalFromConditions(conditions *types.Condition) []types.Principal {
	principals := make([]types.Principal, 0)

	// Common principal-related condition keys and their corresponding principal types
	principalKeys := map[string]PrincipalType{
		"aws:PrincipalArn":         PrincipalTypeAWS,
		"aws:PrincipalAccount":     PrincipalTypeAWS,
		"aws:PrincipalOrgID":       PrincipalTypeAWS,
		"aws:PrincipalServiceName": PrincipalTypeService,
		"aws:SourceArn":            PrincipalTypeAWS,
		"aws:SourceOwner":          PrincipalTypeAWS,
		"aws:SourceAccount":        PrincipalTypeAWS,
	}

	// Process each condition statement
	for _, keyMap := range *conditions {
		for conditionKey, value := range keyMap {
			if principalType, ok := principalKeys[conditionKey]; ok {
				switch principalType {
				case PrincipalTypeAWS:
					principals = append(principals, types.Principal{
						AWS: &value,
					})
				case PrincipalTypeService:
					principals = append(principals, types.Principal{
						Service: &value,
					})
				}
			}
		}
	}

	return principals
}

func extractPrincipalFromResource(resource *types.DynaString) []types.Principal {
	principals := make([]types.Principal, 0)

	// Process each resource string
	for _, resourceStr := range *resource {
		// Check if resource is an IAM ARN
		if strings.Contains(resourceStr, ":iam:") {
			// Extract role/user/group from ARN
			if IsAWSPrincipal(resourceStr) {
				principals = append(principals, types.Principal{
					AWS: types.NewDynaString([]string{resourceStr}),
				})
			}
		}

		// Check if resource is a service principal
		if strings.Contains(resourceStr, ".amazonaws.com") {
			principals = append(principals, types.Principal{
				Service: types.NewDynaString([]string{resourceStr}),
			})
		}
	}

	return principals
}

// IsAWSPrincipal determines if a string represents a valid AWS principal identifier
func IsAWSPrincipal(id string) bool {
	// Check common AWS principal patterns
	validPatterns := []string{
		"arn:aws:iam::",         // IAM ARNs
		"arn:aws:sts::",         // STS ARNs
		"arn:aws:service-role/", // Service-linked roles
		"arn:aws:root",          // Account root
		"AIDA",                  // IAM user ID prefix
		"AROA",                  // IAM role ID prefix
		"AGPA",                  // IAM group ID prefix
	}

	for _, pattern := range validPatterns {
		if strings.HasPrefix(id, pattern) {
			return true
		}
	}

	// Check if it's an account ID
	if len(id) == 12 && isNumeric(id) {
		return true
	}

	return false
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// UniquePrincipals removes duplicate values from a slice of principals
func UniquePrincipals(principals []types.Principal) []types.Principal {
	uniquePrincipals := make([]types.Principal, 0)
	seen := make(map[int]bool)

	for i, principal := range principals {
		duplicate := false
		for j := range uniquePrincipals {
			if reflect.DeepEqual(principal, uniquePrincipals[j]) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			uniquePrincipals = append(uniquePrincipals, principal)
			seen[i] = true
		}
	}

	return uniquePrincipals
}
