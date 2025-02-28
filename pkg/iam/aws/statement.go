package aws

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
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

// PopulateDefaultRequestConditionKeys sets default values for AWS global condition keys
// based on information already present in the RequestContext
func (rc *RequestContext) PopulateDefaultRequestConditionKeys(resourceArn string) {
	// Initialize RequestParameters if nil
	if rc.RequestParameters == nil {
		rc.RequestParameters = make(map[string]string)
	}

	// Parse resource ARN
	resArnParsed, err := arn.Parse(resourceArn)
	if err != nil {
		return
	}

	// Parse principal ARN if available
	var principalArnParsed arn.ARN
	if rc.PrincipalArn != "" {
		principalArnParsed, err = arn.Parse(rc.PrincipalArn)
		if err == nil {
			// Extract principal account ID from ARN if AccountId is not set
			if rc.AccountId == "" {
				rc.AccountId = principalArnParsed.AccountID
			}
		}
	}

	//=======================================
	// Properties of the principal
	//=======================================

	// aws:PrincipalArn - already directly in the struct

	// aws:PrincipalAccount
	if _, ok := rc.RequestParameters["aws:PrincipalAccount"]; !ok && rc.AccountId != "" {
		rc.RequestParameters["aws:PrincipalAccount"] = rc.AccountId
	}

	// aws:PrincipalOrgID
	if _, ok := rc.RequestParameters["aws:PrincipalOrgID"]; !ok && rc.PrincipalOrgId != "" {
		rc.RequestParameters["aws:PrincipalOrgID"] = rc.PrincipalOrgId
	}

	// aws:PrincipalType
	if _, ok := rc.RequestParameters["aws:PrincipalType"]; !ok && rc.PrincipalArn != "" {
		principalType := rc.GetPrincipalType()
		if principalType != PrincipalTypeUnknown {
			rc.RequestParameters["aws:PrincipalType"] = string(principalType)
		}
	}

	// aws:userid
	if _, ok := rc.RequestParameters["aws:userid"]; !ok && rc.PrincipalArn != "" {
		userId := getUserIdFromArn(rc.PrincipalArn)
		if userId != "" {
			rc.RequestParameters["aws:userid"] = userId
		}
	}

	// aws:username - only for IAM users
	if _, ok := rc.RequestParameters["aws:username"]; !ok && rc.GetPrincipalType() == PrincipalTypeUser {
		username := getUsernameFromArn(rc.PrincipalArn)
		if username != "" {
			rc.RequestParameters["aws:username"] = username
		}
	}

	// aws:PrincipalIsAWSService
	if _, ok := rc.RequestParameters["aws:PrincipalIsAWSService"]; !ok {
		if rc.GetPrincipalType() == PrincipalTypeServiceAccount {
			rc.RequestParameters["aws:PrincipalIsAWSService"] = "true"

			// aws:PrincipalServiceName - only set if it's a service principal
			if _, ok := rc.RequestParameters["aws:PrincipalServiceName"]; !ok {
				serviceName := rc.PrincipalArn
				if serviceName != "" {
					rc.RequestParameters["aws:PrincipalServiceName"] = serviceName
				}
			}
		} else {
			rc.RequestParameters["aws:PrincipalIsAWSService"] = "false"
		}
	}

	//=======================================
	// Properties of a role session
	//=======================================

	// Only populate these if we have an IAM role or role session
	principalType := rc.GetPrincipalType()
	if principalType == PrincipalTypeRole || principalType == PrincipalTypeRoleSession {
		// aws:TokenIssueTime
		if _, ok := rc.RequestParameters["aws:TokenIssueTime"]; !ok && !rc.CurrentTime.IsZero() {
			// Set token issue time to 1 hour before current time as a reasonable default
			tokenTime := rc.CurrentTime.Add(-1 * time.Hour)
			rc.RequestParameters["aws:TokenIssueTime"] = tokenTime.Format(time.RFC3339)
		}

		// For assumed roles, we can add source identity if it exists
		if principalType == PrincipalTypeRoleSession {
			if _, ok := rc.RequestParameters["aws:SourceIdentity"]; !ok {
				// This would be extracted from the session in a real scenario
			}
		}
	}

	//=======================================
	// Properties of the network
	//=======================================

	// aws:SourceIp - already in the struct
	if _, ok := rc.RequestParameters["aws:SourceIp"]; !ok && rc.SourceIp != "" {
		rc.RequestParameters["aws:SourceIp"] = rc.SourceIp
	}

	// Don't populate VPC related fields unless we have evidence the request came via a VPC endpoint
	// These would normally come from the request context and we don't want to make up values

	//=======================================
	// Properties of the resource
	//=======================================

	// aws:ResourceAccount
	if _, ok := rc.RequestParameters["aws:ResourceAccount"]; !ok {
		rc.RequestParameters["aws:ResourceAccount"] = resArnParsed.AccountID
	}

	// Note: We don't populate aws:ResourceOrgID or aws:ResourceOrgPaths as they would
	// require knowledge of the organization structure

	//=======================================
	// Properties of the request
	//=======================================

	// aws:CalledVia, aws:CalledViaFirst, aws:CalledViaLast - only set if service principal called
	if rc.GetPrincipalType() == PrincipalTypeServiceAccount {
		if _, ok := rc.RequestParameters["aws:ViaAWSService"]; !ok {
			rc.RequestParameters["aws:ViaAWSService"] = "true"
		}

		serviceName := getServiceNameFromArn(rc.PrincipalArn)
		if serviceName != "" {
			// Set CalledVia array if not present
			if _, ok := rc.RequestParameters["aws:CalledVia"]; !ok {
				rc.RequestParameters["aws:CalledVia"] = serviceName
			}

			// Set first called service if not present
			if _, ok := rc.RequestParameters["aws:CalledViaFirst"]; !ok {
				rc.RequestParameters["aws:CalledViaFirst"] = serviceName
			}

			// Set last called service if not present
			if _, ok := rc.RequestParameters["aws:CalledViaLast"]; !ok {
				rc.RequestParameters["aws:CalledViaLast"] = serviceName
			}
		}
	} else {
		if _, ok := rc.RequestParameters["aws:ViaAWSService"]; !ok {
			rc.RequestParameters["aws:ViaAWSService"] = "false"
		}
	}

	// aws:CurrentTime
	if _, ok := rc.RequestParameters["aws:CurrentTime"]; !ok {
		if rc.CurrentTime.IsZero() {
			rc.RequestParameters["aws:CurrentTime"] = time.Now().Format(time.RFC3339)
		} else {
			rc.RequestParameters["aws:CurrentTime"] = rc.CurrentTime.Format(time.RFC3339)
		}
	}

	// aws:EpochTime
	if _, ok := rc.RequestParameters["aws:EpochTime"]; !ok {
		var epochTime int64
		if rc.CurrentTime.IsZero() {
			epochTime = time.Now().Unix()
		} else {
			epochTime = rc.CurrentTime.Unix()
		}
		rc.RequestParameters["aws:EpochTime"] = strconv.FormatInt(epochTime, 10)
	}

	// aws:RequestedRegion
	if _, ok := rc.RequestParameters["aws:RequestedRegion"]; !ok && resArnParsed.Region != "" {
		rc.RequestParameters["aws:RequestedRegion"] = resArnParsed.Region
	}

	// aws:SecureTransport - default to true unless explicitly set
	if _, ok := rc.RequestParameters["aws:SecureTransport"]; !ok {
		if rc.SecureTransport {
			rc.RequestParameters["aws:SecureTransport"] = "true"
		} else {
			rc.RequestParameters["aws:SecureTransport"] = "false"
		}
	}

	// aws:UserAgent
	if _, ok := rc.RequestParameters["aws:UserAgent"]; !ok && rc.UserAgent != "" {
		rc.RequestParameters["aws:UserAgent"] = rc.UserAgent
	}

	// aws:SourceAccount - derived from resource account if available
	if _, ok := rc.RequestParameters["aws:SourceAccount"]; !ok && resArnParsed.AccountID != "" {
		rc.RequestParameters["aws:SourceAccount"] = resArnParsed.AccountID
	}

	// aws:SourceArn - use the resource ARN
	if _, ok := rc.RequestParameters["aws:SourceArn"]; !ok {
		rc.RequestParameters["aws:SourceArn"] = resourceArn
	}
}

// getUserIdFromArn extracts the user ID portion from ARN
func getUserIdFromArn(principalArn string) string {
	if principalArn == "" {
		return ""
	}

	arnParsed, err := arn.Parse(principalArn)
	if err != nil {
		return ""
	}

	// Extract UserID based on ARN type
	resource := arnParsed.Resource

	switch {
	case strings.HasPrefix(resource, "user/"):
		// For IAM users, the ID is the full ARN
		return principalArn
	case strings.HasPrefix(resource, "role/"):
		// For IAM roles, the ID is the full ARN
		return principalArn
	case strings.HasPrefix(resource, "assumed-role/"):
		// For assumed roles, parse out the role name and session
		parts := strings.Split(strings.TrimPrefix(resource, "assumed-role/"), "/")
		if len(parts) >= 2 {
			return arnParsed.AccountID + ":" + parts[0] + ":" + parts[1]
		}
	case resource == "root":
		// For root users, the ID is account-id
		return arnParsed.AccountID
	}

	return ""
}

// getUsernameFromArn extracts the username from an ARN
func getUsernameFromArn(principalArn string) string {
	if principalArn == "" {
		return ""
	}

	arnParsed, err := arn.Parse(principalArn)
	if err != nil {
		return ""
	}

	// Extract username based on ARN type
	resource := arnParsed.Resource

	if strings.HasPrefix(resource, "user/") {
		// Extract username from the resource part
		return strings.TrimPrefix(resource, "user/")
	}

	// Not a user ARN
	return ""
}

// getServiceNameFromArn extracts the service name from a service principal ARN
func getServiceNameFromArn(principalArn string) string {
	if principalArn == "" {
		return ""
	}

	arnParsed, err := arn.Parse(principalArn)
	if err != nil {
		return ""
	}

	// For service principals, the service is in the ARN service field
	// or in the resource for legacy formats
	if strings.HasSuffix(arnParsed.Service, ".amazonaws.com") {
		return arnParsed.Service
	}

	// Check for service name in resource for legacy formats
	resource := arnParsed.Resource
	if strings.Contains(resource, ".amazonaws.com") {
		parts := strings.Split(resource, ".")
		if len(parts) > 0 {
			return parts[0] + ".amazonaws.com"
		}
	}

	return ""
}

// GetPrincipalType parses the ARN to determine the principal type
func (rc *RequestContext) GetPrincipalType() PrincipalType {
	if rc.PrincipalArn == "" {
		return PrincipalTypeUnknown
	}

	// Parse ARN components
	parts := strings.Split(rc.PrincipalArn, ":")
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
	case strings.Contains(rc.PrincipalArn, ":root"):
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
