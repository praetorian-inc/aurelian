package aws

import (
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nebula/pkg/types"
)

func evaluateStatement(stmt *types.PolicyStatement, requestedAction, requestedResource string, context *RequestContext) *StatementEvaluation {
	eval := &StatementEvaluation{
		ImplicitDeny: true, // Start with implicit deny as default
		Origin:       stmt.OriginArn,
	}

	// Evaluate Principal/NotPrincipal first
	// For resource-based policies, principal is required (implicit deny if missing)
	// For identity-based policies, principal should not be present
	if stmt.Principal != nil || stmt.NotPrincipal != nil {
		if context == nil || context.PrincipalArn == "" {
			// No principal in request context - implicit deny
			return eval
		}

		if stmt.NotPrincipal != nil {
			// NotPrincipal matches if the request principal does NOT match any specified principals
			eval.MatchedPrincipal = !matchesPrincipal(stmt.NotPrincipal, context.PrincipalArn)
		} else {
			// Regular Principal matches if the request principal matches any specified principal
			eval.MatchedPrincipal = matchesPrincipal(stmt.Principal, context.PrincipalArn)
		}

		// If principals don't match, return implicit deny
		if !eval.MatchedPrincipal {
			return eval
		}
	}

	// Evaluate Action/NotAction
	if stmt.NotAction != nil {
		eval.MatchedAction = !matchesActions(stmt.NotAction, requestedAction)
	} else if stmt.Action != nil {
		eval.MatchedAction = matchesActions(stmt.Action, requestedAction)
	} else {
		return eval
	}

	// If actions don't match, return implicit deny
	if !eval.MatchedAction {
		return eval
	}

	// Evaluate Resource/NotResource
	if stmt.NotResource != nil {
		eval.MatchedResource = !MatchesResources(stmt.NotResource, requestedResource)
	} else if stmt.Resource != nil {
		eval.MatchedResource = MatchesResources(stmt.Resource, requestedResource)
	} else {
		return eval
	}

	// If resources don't match, return implicit deny
	if !eval.MatchedResource {
		return eval
	}

	// Check conditions if present
	if stmt.Condition != nil {
		if !evaluateConditions(stmt.Condition, context) {
			return eval
		}
	}

	// If we get here, all criteria matched
	eval.ImplicitDeny = false

	// Set explicit allow/deny based on Effect
	if strings.EqualFold(stmt.Effect, "Deny") {
		eval.ExplicitDeny = true
	} else {
		eval.ExplicitAllow = true
	}

	return eval
}

func matchesRegexPattern(pattern *regexp.Regexp, input string) bool {
	return pattern.MatchString(input)
}

// matchesPattern handles basic glob pattern matching (case insensitive)
func matchesPattern(pattern, input string) bool {
	// Convert AWS pattern to regex
	pattern = strings.ReplaceAll(pattern, ".", "\\.")
	pattern = strings.ReplaceAll(pattern, "*", ".*")
	pattern = strings.ReplaceAll(pattern, "?", ".")
	pattern = "(?i)^" + pattern + "$" // Add case insensitive flag

	p := regexp.MustCompile(pattern)
	return matchesRegexPattern(p, input)
}

// matchesActions checks if an action matches any in the DynaString
func matchesActions(actions *types.DynaString, requestedAction string) bool {
	for _, action := range *actions {
		if matchesPattern(action, requestedAction) {
			return true
		}
	}
	return false
}

// MatchesResources checks if a resource matches any in the DynaString
func MatchesResources(resources *types.DynaString, requestedResource string) bool {
	for _, resource := range *resources {
		if matchesPattern(resource, requestedResource) {
			return true
		}
	}
	return false
}

// RequestContext holds the evaluation context for conditions
type RequestContext struct {
	PrincipalArn      string
	SourceIp          string
	UserAgent         string
	CurrentTime       time.Time
	SecureTransport   bool
	ResourceTags      map[string]string
	RequestTags       map[string]string
	PrincipalOrgId    string
	AccountId         string
	RequestParameters map[string]string
}

// GetPrincipalType parses the ARN to determine the principal type
func (ctx *RequestContext) GetPrincipalType() PrincipalType {
	if ctx.PrincipalArn == "" {
		return PrincipalTypeUnknown
	}

	// Parse ARN components
	parts := strings.Split(ctx.PrincipalArn, ":")
	if len(parts) < 6 {
		return PrincipalTypeUnknown
	}

	// Get the resource section
	resource := parts[5]
	resourceParts := strings.Split(resource, "/")

	switch {
	case strings.HasPrefix(resourceParts[1], "user/"):
		return PrincipalTypeUser
	case strings.HasPrefix(resourceParts[1], "role/"):
		return PrincipalTypeRole
	case strings.HasPrefix(resourceParts[1], "assumed-role/"):
		return PrincipalTypeRoleSession
	case strings.HasPrefix(resourceParts[1], "federated-user/"):
		return PrincipalTypeFederatedUser
	case strings.Contains(ctx.PrincipalArn, ":root"):
		return PrincipalTypeRoot
	case strings.Contains(resource, ".amazonaws.com"):
		return PrincipalTypeServiceAccount
	default:
		return PrincipalTypeUnknown
	}
}

// matchesPrincipal checks if the requestedPrincipal matches the principal definition
func matchesPrincipal(principal *types.Principal, requestedPrincipal string) bool {
	// Handle nil principal
	if principal == nil {
		return false
	}

	if principal.AWS != nil {
		for _, aws := range *principal.AWS {
			if strings.HasSuffix(aws, ":root") {
				aws = strings.Replace(aws, ":root", "*", 1)
			}
			if matchesPattern(aws, requestedPrincipal) {
				return true
			}
		}
	}

	if principal.Service != nil {
		for _, service := range *principal.Service {
			if matchesPattern(service, requestedPrincipal) {
				return true
			}
		}
	}

	if principal.Federated != nil {
		for _, federated := range *principal.Federated {
			if matchesPattern(federated, requestedPrincipal) {
				return true
			}
		}
	}

	if principal.CanonicalUser != nil {
		for _, canonicalUser := range *principal.CanonicalUser {
			if matchesPattern(canonicalUser, requestedPrincipal) {
				return true
			}
		}
	}

	return false
}
