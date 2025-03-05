package aws

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/praetorian-inc/nebula/pkg/types"
)

// evaluateStatement evaluates a policy statement against a request context
func evaluateStatement(stmt *types.PolicyStatement, requestedAction, requestedResource string, context *RequestContext) *StatementEvaluation {
	eval := &StatementEvaluation{
		ImplicitDeny: true, // Start with implicit deny as default
		Origin:       stmt.OriginArn,
	}

	// Evaluate Principal/NotPrincipal first (if present)
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
		conditionEval := evaluateConditions(stmt.Condition, context)
		eval.ConditionEvaluation = conditionEval

		// If conditions explicitly failed, return with implicit deny
		if !conditionEval.Allowed() {
			return eval
		}
	}

	// If we get here, all criteria matched or were inconclusive
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

// RequestContext holds values that can be evaluated in policy conditions
type RequestContext struct {
	// Principal Properties
	PrincipalArn      string            // The ARN of the principal making the request
	PrincipalTags     map[string]string // Tags associated with the principal
	PrincipalOrgID    string            // AWS Organizations ID for principal
	PrincipalOrgPaths []string          // AWS Organizations paths for principal
	PrincipalAccount  string            // Account ID of the principal
	PrincipalType     string            // Type of principal (user, role, etc)
	PrincipalUsername string            // Username if principal is an IAM user

	// Role Session Properties
	RoleSessionName               string    // Name of assumed role session
	FederatedProvider             string    // Identity provider for federation
	TokenIssueTime                time.Time // When temporary credentials were issued
	SourceIdentity                string    // Identity that assumed the role
	AssumedRoot                   *bool     // Whether role was assumed by root account
	MultiFactorAuthAge            int       // Age of MFA auth
	MultiFactorAuthPresent        *bool     // Whether MFA was used
	ChatbotSourceArn              string    // ARN of the chatbot that invoked the action
	Ec2InstanceSourceVpc          string    // VPC ID of the EC2 instance
	Ec2InstanceSourcePrivateIPv4  string    // Private IP of the EC2 instance
	ec2_RoleDelivery              string    // Role delivery method
	ec2_SourceInstanceArn         string    // ARN of the source instance
	glue_RoleAssumedBy            string    // ARN of the role assuming the role
	glue_CredentialIssuingService string    // Service issuing the credentials
	lambda_SourceFunctionArn      string    // ARN of the source Lambda functionj
	ssm_SourceInstanceArn         string    // ARN of the source instance
	identitystore_UserId          string    // User ID of the principal

	// Network Properties
	SourceIP    string // IP address request originated from
	SourceVPC   string // VPC ID if request via VPC endpoint
	SourceVPCE  string // VPC endpoint ID
	VPCSourceIP string // Private IP if request via VPC

	// Resource Properties
	ResourceTags     map[string]string // Tags on the target resource
	ResourceAccount  string            // Account ID owning the resource
	ResourceOrgID    string            // Org ID owning the resource
	ResourceOrgPaths []string          // Org paths for the resource

	// Request Properties
	CalledVia       []string          // Chain of services that made request
	CalledViaFirst  string            // First service in the chain
	CalledViaLast   string            // Last service in the chain
	ViaAWSService   *bool             // Whether request is from AWS service
	CurrentTime     time.Time         // Current time
	Referer         string            // HTTP referer header
	RequestedRegion string            // Region request was made to
	SecureTransport *bool             // Whether request used TLS
	SourceAccount   string            // Account of resource making request
	SourceArn       string            // ARN of resource making request
	SourceOrgID     string            // Org ID of resource making request
	SourceOrgPaths  []string          // Org paths of resource making request
	UserAgent       string            // User agent making request
	RequestTags     map[string]string // Tags in the request

	// Additional context passed by services
	RequestParameters map[string]string // Raw key-value pairs from request
}

func Bool(b bool) *bool {
	return &b
}

// NewRequestContext creates a new RequestContext with initialized maps
func NewRequestContext() *RequestContext {
	return &RequestContext{
		PrincipalTags:     make(map[string]string),
		ResourceTags:      make(map[string]string),
		RequestTags:       make(map[string]string),
		RequestParameters: make(map[string]string),
	}
}

// PopulateDefaultRequestConditionKeys sets default values for AWS global condition keys
// based on information already present in the RequestContext
func (rc *RequestContext) PopulateDefaultRequestConditionKeys(resourceArn string) error {
	// Initialize maps if nil
	if rc.PrincipalTags == nil {
		rc.PrincipalTags = make(map[string]string)
	}
	if rc.ResourceTags == nil {
		rc.ResourceTags = make(map[string]string)
	}
	if rc.RequestTags == nil {
		rc.RequestTags = make(map[string]string)
	}
	if rc.RequestParameters == nil {
		rc.RequestParameters = make(map[string]string)
	}

	// Parse resource ARN
	resArnParsed, err := arn.Parse(resourceArn)
	if err != nil {
		return fmt.Errorf("failed to parse resource ARN: %w", err)
	}

	// Parse principal ARN if available
	var principalArnParsed arn.ARN
	if rc.PrincipalArn != "" {
		principalArnParsed, err = arn.Parse(rc.PrincipalArn)
		if err == nil && rc.PrincipalAccount == "" {
			rc.PrincipalAccount = principalArnParsed.AccountID
		}
	}

	//=======================================
	// Properties of the principal
	//=======================================

	// Determine principal type and related fields
	principalType := determinePrincipalType(rc.PrincipalArn)
	rc.PrincipalType = string(principalType)

	// Extract username for IAM users
	if principalType == PrincipalTypeUser {
		rc.PrincipalUsername = getUsernameFromArn(rc.PrincipalArn)
	}

	// Principal service info
	if principalType == PrincipalTypeService || principalType == PrincipalTypeServiceAccount {
		trueValue := true
		rc.ViaAWSService = &trueValue
		serviceName := getServiceNameFromArn(rc.PrincipalArn)

		// Set CalledVia chain
		if len(rc.CalledVia) == 0 && serviceName != "" {
			rc.CalledVia = []string{serviceName}
		}
	}

	//=======================================
	// Properties of role sessions
	//=======================================

	// Only populate session-specific fields for role sessions
	switch principalType {
	case PrincipalTypeRole, PrincipalTypeRoleSession:
		// Set token issue time if not already set
		if rc.TokenIssueTime.IsZero() {
			// Default to 1 hour before current time
			if rc.CurrentTime.IsZero() {
				rc.TokenIssueTime = time.Now().Add(-1 * time.Hour)
			} else {
				rc.TokenIssueTime = rc.CurrentTime.Add(-1 * time.Hour)
			}
		}
	case PrincipalTypeFederatedUser:
		// Set federated provider if using federation
		if rc.FederatedProvider == "" && principalArnParsed.Service == "sts" {
			parts := strings.Split(principalArnParsed.Resource, "/")
			if len(parts) >= 2 {
				rc.FederatedProvider = parts[0]
			}
		}
	}

	//=======================================
	// Properties of the network
	//=======================================

	// Network properties are mostly set directly during request processing
	// We don't set defaults here to avoid making assumptions

	//=======================================
	// Properties of the resource
	//=======================================

	// Set resource account
	if rc.ResourceAccount == "" {
		rc.ResourceAccount = resArnParsed.AccountID
	}

	// Note: We don't set ResourceOrgID or ResourceOrgPaths as they require
	// knowledge of the organization structure

	//=======================================
	// Properties of the request
	//=======================================

	// Set request time if not already set
	if rc.CurrentTime.IsZero() {
		rc.CurrentTime = time.Now()
	}

	// Set requested region if not set, default to us-east-1 if not present for global services
	if rc.RequestedRegion == "" && resArnParsed.Region != "" {
		rc.RequestedRegion = resArnParsed.Region
	} else if rc.RequestedRegion == "" {
		rc.RequestedRegion = "us-east-1"
	}

	// Set source info for cross-service calls
	// if rc.SourceArn == "" {
	// 	rc.SourceArn = resourceArn
	// }
	if rc.SourceAccount == "" {
		rc.SourceAccount = resArnParsed.AccountID
	}

	return nil
}

// determinePrincipalType analyzes an ARN to determine the principal type
func determinePrincipalType(principalArn string) PrincipalType {
	if principalArn == "" {
		return PrincipalTypeUnknown
	}

	arnParsed, err := arn.Parse(principalArn)
	if err != nil {
		return PrincipalTypeUnknown
	}

	// Check for service principals
	if strings.HasSuffix(arnParsed.AccountID, ".amazonaws.com") {
		return PrincipalTypeService
	}

	// Parse the resource section based on service
	switch arnParsed.Service {
	case "iam":
		resourceParts := strings.Split(arnParsed.Resource, "/")
		if len(resourceParts) < 2 {
			return PrincipalTypeUnknown
		}

		switch resourceParts[0] {
		case "user":
			return PrincipalTypeUser
		case "role":
			return PrincipalTypeRole
		case "root":
			return PrincipalTypeRoot
		}

	case "sts":
		resourceParts := strings.Split(arnParsed.Resource, "/")
		if len(resourceParts) < 2 {
			return PrincipalTypeUnknown
		}

		switch resourceParts[0] {
		case "assumed-role":
			return PrincipalTypeRoleSession
		case "federated-user":
			return PrincipalTypeFederatedUser
		}
	}

	// Check for canonical user format
	if strings.HasPrefix(arnParsed.Resource, "canonical-user/") {
		return PrincipalTypeCanonicalUser
	}

	return PrincipalTypeUnknown
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
